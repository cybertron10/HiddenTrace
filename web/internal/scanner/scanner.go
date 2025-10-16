package scanner

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"HiddenTrace/web/internal/database"
	"HiddenTrace/internal/enhancedCrawler"
	"HiddenTrace/internal/paramsmapper"
	"HiddenTrace/internal/scanningData"
	"github.com/google/uuid"
)

type Service struct {
	db *database.DB
	// Map to track running fuzzing processes for cancellation
	runningFuzzing map[string]context.CancelFunc
	fuzzingMutex   sync.RWMutex
}

type ScanRequest struct {
	TargetURL  string            `json:"target_url" binding:"required,url"`
	MaxDepth   int               `json:"max_depth" binding:"min=1,max=50"`
	MaxPages   int               `json:"max_pages" binding:"min=1,max=100000"`
	Headers    map[string]string `json:"headers"`
}

type ScanResponse struct {
	ScanID int    `json:"scan_id"`
	Status string `json:"status"`
	Message string `json:"message"`
}

func NewService(db *database.DB) *Service {
	return &Service{
		db:             db,
		runningFuzzing: make(map[string]context.CancelFunc),
	}
}

// StartScan initiates a new security scan
func (s *Service) StartScan(userID int, req *ScanRequest) (*ScanResponse, error) {
	// Generate unique scan UUID
	scanUUID := uuid.New().String()
	
	// Convert headers to JSON
	headersJSON, err := json.Marshal(req.Headers)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal headers: %v", err)
	}

	// Create scan record
	result, err := s.db.Exec(`
		INSERT INTO scans (scan_uuid, user_id, target_url, max_depth, max_pages, headers, status) 
		VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
		scanUUID, userID, req.TargetURL, req.MaxDepth, req.MaxPages, string(headersJSON))
	if err != nil {
		return nil, err
	}

	scanID, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	// Start scan in background
	go s.runScan(int(scanID), scanUUID, req)

	return &ScanResponse{
		ScanID:  int(scanID),
		Status:  "pending",
		Message: "Scan initiated successfully",
	}, nil
}

// runScan executes the actual scanning process
func (s *Service) runScan(scanID int, scanUUID string, req *ScanRequest) {
	log.Printf("runScan called - ScanID: %d, ScanUUID: %s, TargetURL: %s", scanID, scanUUID, req.TargetURL)
	
	// Update status to running
	now := time.Now()
	_, err := s.db.Exec(`
		UPDATE scans SET status = 'running', started_at = ?, progress = 0 
		WHERE id = ?`,
		now, scanID)
	if err != nil {
		log.Printf("Error updating scan status: %v", err)
		return
	}

	// Create output directory for this scan using UUID
	scanDir := filepath.Join("data", "scans", scanUUID)
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		log.Printf("Error creating scan directory: %v", err)
		s.updateScanStatus(scanID, "failed", 0)
		return
	}

	// Update progress
	s.updateScanProgress(scanID, 10)

	// Run enhanced crawler
	log.Printf("Starting scan %d for URL: %s", scanID, req.TargetURL)
	log.Printf("DEBUG: Headers being passed to crawler: %v", req.Headers)
	log.Printf("DEBUG: About to call EnhancedCrawl with startURL: %s", req.TargetURL)
	
	crawlResult, err := enhancedCrawler.EnhancedCrawl(
		req.TargetURL, 
		req.MaxDepth, 
		req.MaxPages, 
		req.Headers,
	)
	if err != nil {
		log.Printf("Error during crawling: %v", err)
		s.updateScanStatus(scanID, "failed", 0)
		return
	}

	// Check if crawler returned any results
	if len(crawlResult.URLs) == 0 && len(crawlResult.FormFields) == 0 && len(crawlResult.JavaScriptAPIs) == 0 {
		log.Printf("Crawler returned no results for %s - possible authentication issue", req.TargetURL)
		s.updateScanStatus(scanID, "failed", 0)
		return
	}

	log.Printf("Crawler found %d URLs, %d forms, %d JS APIs for %s", 
		len(crawlResult.URLs), len(crawlResult.FormFields), len(crawlResult.JavaScriptAPIs), req.TargetURL)
	
	// Log the first few URLs discovered to see what paths were crawled
	if len(crawlResult.URLs) > 0 {
		log.Printf("DEBUG: First 10 URLs discovered by crawler:")
		for i, url := range crawlResult.URLs {
			if i >= 10 { break }
			log.Printf("DEBUG: URL %d: %s", i+1, url)
		}
	}

	// Update progress
	s.updateScanProgress(scanID, 50)

	// Create structured scanning data
	scanData := scanningData.CreateScanningData(
		crawlResult.URLs,
		crawlResult.FormFields,
		crawlResult.JavaScriptAPIs,
		crawlResult.HiddenFields,
		crawlResult.POSTEndpoints,
	)
	
	// Add custom headers to all endpoints
	for i := range scanData.GETEndpoints {
		scanData.GETEndpoints[i].Headers = req.Headers
	}
	for i := range scanData.POSTEndpoints {
		scanData.POSTEndpoints[i].Headers = req.Headers
	}
	for i := range scanData.JSEndpoints {
		scanData.JSEndpoints[i].Headers = req.Headers
	}

	// Update progress
	s.updateScanProgress(scanID, 70)

	// Save results to database
	log.Printf("Saving scan results for scan %d: %d GET, %d POST, %d JS endpoints", 
		scanID, len(scanData.GETEndpoints), len(scanData.POSTEndpoints), len(scanData.JSEndpoints))
	
	err = s.saveScanResults(scanID, scanUUID, scanData)
	if err != nil {
		log.Printf("Error saving scan results: %v", err)
		s.updateScanStatus(scanID, "failed", 0)
		return
	}
	
	log.Printf("Successfully saved scan results for scan %d", scanID)

	// Update progress
	s.updateScanProgress(scanID, 90)

	// Save files
	err = s.saveScanFiles(scanID, scanUUID, scanDir, scanData)
	if err != nil {
		log.Printf("Error saving scan files: %v", err)
		// Don't fail the scan for file save errors
	}


	// Update progress and status
	s.updateScanProgress(scanID, 100)
	s.updateScanStatus(scanID, "completed", 100)

	log.Printf("Scan %d completed successfully", scanID)
}

// saveScanResults saves discovered endpoints to database
func (s *Service) saveScanResults(scanID int, scanUUID string, scanData *scanningData.ScanningData) error {
	// Save GET endpoints
	for _, endpoint := range scanData.GETEndpoints {
		// Debug logging for parameters before saving
		for param := range endpoint.Parameters {
			if param == "amp;other" {
				log.Printf("DEBUG: Found problematic parameter 'amp;other' in URL: %s", endpoint.URL)
			}
			log.Printf("DEBUG: Saving GET parameter to database: '%s'", param)
		}
		paramsJSON, _ := json.Marshal(endpoint.Parameters)
		headersJSON, _ := json.Marshal(endpoint.Headers)
		
		_, err := s.db.Exec(`
			INSERT INTO scan_results (scan_id, scan_uuid, endpoint_type, url, method, parameters, headers, description)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			scanID, scanUUID, "get", endpoint.URL, endpoint.Method, string(paramsJSON), 
			string(headersJSON), endpoint.Description)
		if err != nil {
			return err
		}
	}

	// Save POST endpoints
	for _, endpoint := range scanData.POSTEndpoints {
		// Debug logging for parameters before saving
		for param := range endpoint.Parameters {
			log.Printf("DEBUG: Saving POST parameter to database: '%s'", param)
		}
		paramsJSON, _ := json.Marshal(endpoint.Parameters)
		formDataJSON, _ := json.Marshal(endpoint.FormData)
		headersJSON, _ := json.Marshal(endpoint.Headers)
		
		_, err := s.db.Exec(`
			INSERT INTO scan_results (scan_id, scan_uuid, endpoint_type, url, method, parameters, form_data, headers, description)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			scanID, scanUUID, "post", endpoint.URL, endpoint.Method, string(paramsJSON), 
			string(formDataJSON), string(headersJSON), endpoint.Description)
		if err != nil {
			return err
		}
	}

	// Save JS endpoints
	for _, endpoint := range scanData.JSEndpoints {
		paramsJSON, _ := json.Marshal(endpoint.Parameters)
		headersJSON, _ := json.Marshal(endpoint.Headers)
		
		_, err := s.db.Exec(`
			INSERT INTO scan_results (scan_id, scan_uuid, endpoint_type, url, method, parameters, headers, description)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			scanID, scanUUID, "js_api", endpoint.URL, endpoint.Method, string(paramsJSON), 
			string(headersJSON), endpoint.Description)
		if err != nil {
			return err
		}
	}

	// Save statistics
	_, err := s.db.Exec(`
		INSERT INTO scan_statistics (scan_id, scan_uuid, total_endpoints, get_endpoints, post_endpoints, js_endpoints, total_parameters)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		scanID, scanUUID, scanData.Summary.TotalEndpoints, scanData.Summary.GETCount, 
		scanData.Summary.POSTCount, scanData.Summary.JSCount, scanData.Summary.TotalParams)
	
	return err
}

// saveScanFiles saves generated files
func (s *Service) saveScanFiles(scanID int, scanUUID string, scanDir string, scanData *scanningData.ScanningData) error {
	// Save JSON data
	jsonFile := filepath.Join(scanDir, "scan_results.json")
	err := scanData.SaveToFile(jsonFile)
	if err != nil {
		return err
	}

	// Save XSS endpoints
	xssFile := filepath.Join(scanDir, "xss_endpoints.txt")
	err = scanData.SaveEndpointsForXSS(xssFile)
	if err != nil {
		return err
	}

	// Save parameters to file
	paramsFile := filepath.Join(scanDir, "params.txt")
	err = s.saveParametersToFile(scanData, paramsFile)
	if err != nil {
		log.Printf("Error saving parameters file: %v", err)
		// Don't fail the scan for parameter file errors
	}

	// Generate brutewordlist by combining parameters with predefined wordlist
	brutewordlistFile := filepath.Join(scanDir, "brutewordlist.txt")
	err = s.generateBrutewordlist(scanData, brutewordlistFile)
	if err != nil {
		log.Printf("Error generating brutewordlist: %v", err)
		// Don't fail the scan for brutewordlist errors
	}

	// Create allurls.txt file for Axiom integration
	allURLsFile := filepath.Join(scanDir, "allurls.txt")
	err = s.createAllURLsFileFromScanData(scanData, allURLsFile)
	if err != nil {
		log.Printf("Error creating allurls.txt file: %v", err)
		// Don't fail the scan for allurls.txt errors
	} else {
		log.Printf("Created allurls.txt file with all discovered URLs")
	}

	// Record files in database
	files := []struct {
		fileType string
		filePath string
	}{
		{"json", jsonFile},
		{"txt", xssFile},
		{"params", paramsFile},
		{"brutewordlist", brutewordlistFile},
		{"allurls", allURLsFile},
	}

	for _, file := range files {
		info, err := os.Stat(file.filePath)
		if err != nil {
			continue
		}

		_, err = s.db.Exec(`
			INSERT INTO scan_files (scan_id, scan_uuid, file_type, file_path, file_size)
			VALUES (?, ?, ?, ?, ?)`,
			scanID, scanUUID, file.fileType, file.filePath, info.Size())
		if err != nil {
			log.Printf("Error saving file record: %v", err)
		}
	}

	return nil
}

// saveParametersToFile extracts and saves all parameters to a file
func (s *Service) saveParametersToFile(scanData *scanningData.ScanningData, filename string) error {
	paramSet := make(map[string]bool)
	
	// Extract parameters from GET endpoints
	for _, endpoint := range scanData.GETEndpoints {
		for param := range endpoint.Parameters {
			paramSet[param] = true
		}
	}
	
	// Extract parameters from POST endpoints
	for _, endpoint := range scanData.POSTEndpoints {
		for param := range endpoint.Parameters {
			paramSet[param] = true
		}
		for param := range endpoint.FormData {
			paramSet[param] = true
		}
	}
	
	// Extract parameters from JS endpoints
	for _, endpoint := range scanData.JSEndpoints {
		for param := range endpoint.Parameters {
			paramSet[param] = true
		}
	}
	
	// Convert map to sorted slice
	var parameters []string
	for param := range paramSet {
		parameters = append(parameters, param)
	}
	
	// Sort parameters alphabetically
	sort.Strings(parameters)
	
	// Save to file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Write parameters (clean wordlist without comments)
	for _, param := range parameters {
		_, err = file.WriteString(param + "\n")
		if err != nil {
			return err
		}
	}
	
	return nil
}

// generateBrutewordlist combines extracted parameters with predefined wordlist
func (s *Service) generateBrutewordlist(scanData *scanningData.ScanningData, filename string) error {
	log.Printf("DEBUG: Generating brutewordlist for file: %s", filename)
	
	// Extract unique parameters from scan data
	paramSet := make(map[string]bool)
	
	// Extract parameters from GET endpoints
	for _, endpoint := range scanData.GETEndpoints {
		for param := range endpoint.Parameters {
			paramSet[param] = true
		}
	}
	
	// Extract parameters from POST endpoints
	for _, endpoint := range scanData.POSTEndpoints {
		for param := range endpoint.Parameters {
			paramSet[param] = true
		}
		for param := range endpoint.FormData {
			paramSet[param] = true
		}
	}
	
	// Extract parameters from JS endpoints
	for _, endpoint := range scanData.JSEndpoints {
		for param := range endpoint.Parameters {
			paramSet[param] = true
		}
	}
	
	// Convert to sorted slice
	var parameters []string
	for param := range paramSet {
		parameters = append(parameters, param)
	}
	sort.Strings(parameters)
	
	log.Printf("DEBUG: Extracted %d unique parameters from scan data", len(parameters))
	
	// If no parameters were extracted, log a warning but continue with predefined wordlist
	if len(parameters) == 0 {
		log.Printf("WARNING: No parameters extracted from scan data - will use only predefined wordlist")
	}
	
	// Read predefined wordlist
	wordlistPath := filepath.Join("wordlist", "wordlist.txt")
	log.Printf("DEBUG: Trying to read wordlist from: %s", wordlistPath)
	wordlistContent, err := os.ReadFile(wordlistPath)
	if err != nil {
		// Try alternative path
		altPath := filepath.Join("..", "wordlist", "wordlist.txt")
		wordlistContent, err = os.ReadFile(altPath)
		if err != nil {
			log.Printf("Warning: Could not read predefined wordlist from %s or %s: %v", wordlistPath, altPath, err)
			// Continue with just the extracted parameters
			wordlistContent = []byte{}
		} else {
			log.Printf("Successfully loaded wordlist from alternative path: %s", altPath)
		}
	} else {
		log.Printf("Successfully loaded wordlist from: %s", wordlistPath)
	}
	
	// Validate that we have at least some content to write
	if len(parameters) == 0 && len(wordlistContent) == 0 {
		log.Printf("ERROR: No parameters extracted and no predefined wordlist found - cannot create brutewordlist")
		return fmt.Errorf("no parameters or wordlist available for fuzzing")
	}
	
	// Create brutewordlist file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Write extracted parameters first
	paramCount := 0
	for _, param := range parameters {
		_, err = file.WriteString(param + "\n")
		if err != nil {
			return err
		}
		paramCount++
	}
	log.Printf("DEBUG: Wrote %d extracted parameters to brutewordlist", paramCount)
	
	// Write predefined wordlist content
	wordlistCount := 0
	if len(wordlistContent) > 0 {
		// Count lines in wordlist content
		lines := strings.Split(string(wordlistContent), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				wordlistCount++
			}
		}
		
		_, err = file.WriteString(string(wordlistContent))
		if err != nil {
			return err
		}
		log.Printf("DEBUG: Wrote %d lines of predefined wordlist content (%d bytes)", wordlistCount, len(wordlistContent))
	} else {
		log.Printf("DEBUG: No predefined wordlist content to write")
	}
	
	totalItems := paramCount + wordlistCount
	log.Printf("Generated brutewordlist with %d total items (%d extracted parameters + %d predefined wordlist items)", totalItems, paramCount, wordlistCount)
	
	// Validate the file was created and has content
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("failed to verify brutewordlist file creation: %v", err)
	}
	
	if fileInfo.Size() == 0 {
		return fmt.Errorf("brutewordlist file was created but is empty")
	}
	
	log.Printf("DEBUG: Brutewordlist file created successfully: %s (%d bytes)", filename, fileInfo.Size())
	return nil
}

// RunParameterFuzzing runs parameter fuzzing using paramsmapper tool
func (s *Service) RunParameterFuzzing(scanUUID string, userID int, chunkSize int) {
	log.Printf("Starting parameter fuzzing for scan %s", scanUUID)
	
	// Verify scan exists and user has access (admin can access any scan)
	// Check if user is admin by getting user from database
	user, err := s.GetUserByID(userID)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		return
	}
	if user.Role == "admin" {
		// Admin can access any scan
		_, err := s.GetScanByUUIDForAdmin(scanUUID)
		if err != nil {
			log.Printf("Error getting scan for fuzzing: %v", err)
			return
		}
	} else {
		// Regular user can only access their own scans
		_, err := s.GetScanByUUID(scanUUID, userID)
		if err != nil {
			log.Printf("Error getting scan for fuzzing: %v", err)
			return
		}
	}
	
    // Before starting, clear any previous hidden-URL reports so results are fresh
    if err := s.clearPreviousFuzzReports(scanUUID); err != nil {
        log.Printf("WARNING: Failed to clear previous fuzz reports: %v", err)
    }

    // Get scan results
	results, err := s.GetScanResultsByUUID(scanUUID, userID)
	if err != nil {
		log.Printf("Error getting scan results for fuzzing: %v", err)
		return
	}
	
	// Create scan directory path using UUID
	scanDir := filepath.Join("data", "scans", scanUUID)
	
	// Check if brutewordlist exists
	brutewordlistFile := filepath.Join(scanDir, "brutewordlist.txt")
	if _, err := os.Stat(brutewordlistFile); os.IsNotExist(err) {
		log.Printf("Brutewordlist not found, generating it first")
		// Generate brutewordlist from scan results
		scanData := s.convertResultsToScanningData(results)
		err = s.generateBrutewordlist(scanData, brutewordlistFile)
		if err != nil {
			log.Printf("Error generating brutewordlist: %v", err)
			// Write error to progress file
			s.writeProgressFile(scanDir, "fuzz_progress.json", paramsmapper.ProgressInfo{
				Current:    0,
				Total:      0,
				Percentage: 0,
				Stage:      "error",
				Message:    fmt.Sprintf("Failed to generate brutewordlist: %v", err),
				Discovered: 0,
			})
			return
		}
	} else {
		log.Printf("Brutewordlist already exists: %s", brutewordlistFile)
		// Validate that the existing file is not empty
		fileInfo, err := os.Stat(brutewordlistFile)
		if err != nil {
			log.Printf("Error checking brutewordlist file: %v", err)
			return
		}
		if fileInfo.Size() == 0 {
			log.Printf("WARNING: Existing brutewordlist file is empty, regenerating...")
			scanData := s.convertResultsToScanningData(results)
			err = s.generateBrutewordlist(scanData, brutewordlistFile)
			if err != nil {
				log.Printf("Error regenerating brutewordlist: %v", err)
				s.writeProgressFile(scanDir, "fuzz_progress.json", paramsmapper.ProgressInfo{
					Current:    0,
					Total:      0,
					Percentage: 0,
					Stage:      "error",
					Message:    fmt.Sprintf("Failed to regenerate brutewordlist: %v", err),
					Discovered: 0,
				})
				return
			}
		}
	}
	
	// Separate GET and POST URLs
	var getURLs []string
	var postURLs []string
	
	for _, result := range results {
		if result.EndpointType == "get" {
			getURLs = append(getURLs, result.URL)
		} else if result.EndpointType == "post" {
			postURLs = append(postURLs, result.URL)
		}
	}
	
	// Create URLs files
	getURLsFile := filepath.Join(scanDir, "get_urls.txt")
	postURLsFile := filepath.Join(scanDir, "post_urls.txt")
	
	// Write GET URLs
	if len(getURLs) > 0 {
		err = s.writeURLsToFile(getURLs, getURLsFile)
		if err != nil {
			log.Printf("Error writing GET URLs: %v", err)
		} else {
			log.Printf("Written %d GET URLs to %s", len(getURLs), getURLsFile)
		}
	}
	
	// Write POST URLs
	if len(postURLs) > 0 {
		err = s.writeURLsToFile(postURLs, postURLsFile)
		if err != nil {
			log.Printf("Error writing POST URLs: %v", err)
		} else {
			log.Printf("Written %d POST URLs to %s", len(postURLs), postURLsFile)
		}
	}
	
	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	
	// Store the cancel function for this scan
	s.fuzzingMutex.Lock()
	s.runningFuzzing[scanUUID] = cancel
	s.fuzzingMutex.Unlock()
	
	// Ensure cleanup when function exits
	defer func() {
		s.fuzzingMutex.Lock()
		delete(s.runningFuzzing, scanUUID)
		s.fuzzingMutex.Unlock()
		cancel()
	}()
	
	// Run fuzzing in separate goroutines with cancellation support
	var wg sync.WaitGroup
	
	if len(getURLs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
            s.runParamsmapperForGETWithContext(ctx, getURLsFile, brutewordlistFile, scanDir, chunkSize)
		}()
	}
	
	if len(postURLs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
            s.runParamsmapperForPOSTWithContext(ctx, postURLsFile, brutewordlistFile, scanDir, chunkSize)
		}()
	}
	
	// Wait for all fuzzing to complete or be cancelled
	wg.Wait()
	
	// Create allurls.txt file for Axiom integration
	allURLsFile := filepath.Join(scanDir, "allurls.txt")
	err = s.createAllURLsFile(results, allURLsFile)
	if err != nil {
		log.Printf("Error creating allurls.txt file: %v", err)
	} else {
		log.Printf("Created allurls.txt file with all discovered URLs")
	}
	
	log.Printf("Parameter fuzzing completed for scan %s", scanUUID)
}

// writeURLsToFile writes URLs to a file
func (s *Service) writeURLsToFile(urls []string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	for _, url := range urls {
		_, err = file.WriteString(url + "\n")
		if err != nil {
			return err
		}
	}
	
	return nil
}

// runParamsmapperForGET runs paramsmapper for GET requests
func (s *Service) runParamsmapperForGET(urlsFile, wordlistFile, outputDir string, chunkSize int) {
	log.Printf("Running paramsmapper for GET requests")
	
	reportFile := filepath.Join(outputDir, "get_report.json")
	
	// Load URLs from file
	urls, err := s.loadURLsFromFile(urlsFile)
	if err != nil {
		log.Printf("Error loading URLs from file: %v", err)
		return
	}
	
	// Load wordlist
	params := paramsmapper.LoadWordlist(wordlistFile)
	log.Printf("DEBUG: Loaded %d parameters from wordlist file: %s", len(params), wordlistFile)
	
	// Get custom headers
	customHeaders := s.getCustomHeadersFromScanResults(outputDir)
	
	// Process each URL
	var allResults paramsmapper.Results
	allResults.Params = []string{}
	allResults.FormParams = []string{}
	allResults.TotalRequests = 0
	
	log.Printf("DEBUG: Processing %d URLs for parameter fuzzing", len(urls))
	for i, url := range urls {
		// Check for stop signal before processing each URL
		stopFile := filepath.Join(outputDir, "stop_fuzzing")
		if _, err := os.Stat(stopFile); err == nil {
			log.Printf("DEBUG: Stop signal detected, aborting parameter fuzzing")
			// Write aborted progress
			s.writeProgressFile(outputDir, "get_progress.json", paramsmapper.ProgressInfo{
				Current:    i,
				Total:      len(urls),
				Percentage: (i * 100) / len(urls),
				Stage:      "aborted",
				Message:    "Fuzzing stopped by user",
				Discovered: len(allResults.Params),
			})
			return
		}
		
		log.Printf("DEBUG: Processing URL %d: %s", i+1, url)
		request := paramsmapper.Request{
			URL:         url,
			Method:      "GET",
			ContentType: "form",
			Timeout:     10,
			Headers:     customHeaders,
		}
		
		// Create URL-based progress callback
		urlIndex := i + 1
		totalUrls := len(urls)
		progressCallback := func(progress paramsmapper.ProgressInfo) {
			// Calculate URL-based progress
			urlProgress := (urlIndex - 1) * 100 / totalUrls
			paramProgress := progress.Percentage / totalUrls
			totalProgress := urlProgress + paramProgress
			
			// Update progress info with URL-based calculation
			urlBasedProgress := paramsmapper.ProgressInfo{
				Current:    urlIndex,
				Total:      totalUrls,
				Percentage: totalProgress,
				Stage:      progress.Stage,
				Message:    fmt.Sprintf("Processing URL %d/%d: %s", urlIndex, totalUrls, progress.Message),
				Discovered: progress.Discovered,
			}
			s.writeProgressFile(outputDir, "get_progress.json", urlBasedProgress)
		}
		
        // Use single large chunk so parameters that must work in pairs (e.g., q+url)
        // are tested together and then isolated by recursive bisection
        // Respect configured chunk size (default supplied by handler)
        if chunkSize <= 0 {
            chunkSize = 500
        }
        results := paramsmapper.DiscoverParamsWithProgress(request, params, chunkSize, progressCallback)
		
		// Merge results
		allResults.Params = append(allResults.Params, results.Params...)
		allResults.FormParams = append(allResults.FormParams, results.FormParams...)
		allResults.TotalRequests += results.TotalRequests
	}
	
	// Set request information if we have results but no request set
	if len(allResults.Params) > 0 && allResults.Request.URL == "" && len(urls) > 0 {
		allResults.Request = paramsmapper.Request{
			URL:         urls[0], // Use the first URL
			Method:      "GET",
			ContentType: "form",
			Timeout:     10,
			Headers:     customHeaders,
		}
	}
	
	// Remove duplicates
	allResults.Params = s.removeDuplicates(allResults.Params)
	allResults.FormParams = s.removeDuplicates(allResults.FormParams)
	
	log.Printf("DEBUG: Final results - %d unique params, %d unique form params, %d total requests", 
		len(allResults.Params), len(allResults.FormParams), allResults.TotalRequests)
	
	// Save report
	paramsmapper.SaveReport(reportFile, allResults)
	log.Printf("Paramsmapper GET completed successfully. Found %d parameters, %d form parameters", 
		len(allResults.Params), len(allResults.FormParams))
}

// runParamsmapperForGETWithContext runs paramsmapper for GET requests with context cancellation
func (s *Service) runParamsmapperForGETWithContext(ctx context.Context, urlsFile, wordlistFile, outputDir string, chunkSize int) {
	log.Printf("Running paramsmapper for GET requests with context cancellation")
	
	reportFile := filepath.Join(outputDir, "get_report.json")
	
	// Load URLs from file
	urls, err := s.loadURLsFromFile(urlsFile)
	if err != nil {
		log.Printf("Error loading URLs from file: %v", err)
		return
	}
	
	// Load wordlist
	params := paramsmapper.LoadWordlist(wordlistFile)
	log.Printf("DEBUG: Loaded %d parameters from wordlist file: %s", len(params), wordlistFile)
	
	// Get custom headers
	customHeaders := s.getCustomHeadersFromScanResults(outputDir)
	
	// Process each URL
	var allResults paramsmapper.Results
	allResults.Params = []string{}
	allResults.FormParams = []string{}
	allResults.TotalRequests = 0
	
	log.Printf("DEBUG: Processing %d URLs for parameter fuzzing", len(urls))
	for i, url := range urls {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			log.Printf("DEBUG: Context cancelled, aborting GET parameter fuzzing")
			// Write aborted progress
			s.writeProgressFile(outputDir, "get_progress.json", paramsmapper.ProgressInfo{
				Current:    i,
				Total:      len(urls),
				Percentage: (i * 100) / len(urls),
				Stage:      "aborted",
				Message:    "Fuzzing stopped by user",
				Discovered: len(allResults.Params),
			})
			return
		default:
			// Continue processing
		}
		
		log.Printf("DEBUG: Processing URL %d: %s", i+1, url)
		request := paramsmapper.Request{
			URL:         url,
			Method:      "GET",
			ContentType: "form",
			Timeout:     10,
			Headers:     customHeaders,
		}
		
		// Create URL-based progress callback
		urlIndex := i + 1
		totalUrls := len(urls)
		progressCallback := func(progress paramsmapper.ProgressInfo) {
			// Check for cancellation in progress callback
			select {
			case <-ctx.Done():
				return // Don't update progress if cancelled
			default:
				// Calculate URL-based progress
				urlProgress := (urlIndex - 1) * 100 / totalUrls
				paramProgress := progress.Percentage / totalUrls
				totalProgress := urlProgress + paramProgress
				
				// Update progress info with URL-based calculation
				urlBasedProgress := paramsmapper.ProgressInfo{
					Current:    urlIndex,
					Total:      totalUrls,
					Percentage: totalProgress,
					Stage:      progress.Stage,
					Message:    fmt.Sprintf("Processing URL %d/%d: %s", urlIndex, totalUrls, progress.Message),
					Discovered: progress.Discovered,
				}
				s.writeProgressFile(outputDir, "get_progress.json", urlBasedProgress)
			}
		}
		
        // Run paramsmapper with progress callback
        if chunkSize <= 0 { chunkSize = 500 }
        result := paramsmapper.DiscoverParamsWithProgress(request, params, chunkSize, progressCallback)
		
		// Check for cancellation after paramsmapper completes
		select {
		case <-ctx.Done():
			log.Printf("DEBUG: Context cancelled after paramsmapper, aborting GET parameter fuzzing")
			// Write aborted progress
			s.writeProgressFile(outputDir, "get_progress.json", paramsmapper.ProgressInfo{
				Current:    i + 1,
				Total:      len(urls),
				Percentage: ((i + 1) * 100) / len(urls),
				Stage:      "aborted",
				Message:    "Fuzzing stopped by user",
				Discovered: len(allResults.Params),
			})
			return
		default:
			// Continue processing
		}
		
		// Merge results
		allResults.Params = append(allResults.Params, result.Params...)
		allResults.FormParams = append(allResults.FormParams, result.FormParams...)
		allResults.TotalRequests += result.TotalRequests
		
		// Set request info if not already set
		if allResults.Request.URL == "" {
			allResults.Request = result.Request
		}
	}
	
	// Remove duplicates
	allResults.Params = s.removeDuplicates(allResults.Params)
	allResults.FormParams = s.removeDuplicates(allResults.FormParams)
	
	// Parse and save results
	hiddenUrls, err := s.parseParamsmapperReport(reportFile)
	if err != nil {
		log.Printf("Error parsing paramsmapper report: %v", err)
	} else {
		log.Printf("Parsed %d hidden URLs from report", len(hiddenUrls))
	}
	
	// Save final report
	paramsmapper.SaveReport(reportFile, allResults)
	log.Printf("Paramsmapper GET completed successfully. Found %d parameters, %d form parameters", 
		len(allResults.Params), len(allResults.FormParams))
}

// runParamsmapperForPOST runs paramsmapper for POST requests
func (s *Service) runParamsmapperForPOST(urlsFile, wordlistFile, outputDir string, chunkSize int) {
	log.Printf("Running paramsmapper for POST requests")
	
	reportFile := filepath.Join(outputDir, "post_report.json")
	
	// Load URLs from file
	urls, err := s.loadURLsFromFile(urlsFile)
	if err != nil {
		log.Printf("Error loading URLs from file: %v", err)
		return
	}
	
	// Load wordlist
	params := paramsmapper.LoadWordlist(wordlistFile)
	
	// Get custom headers
	customHeaders := s.getCustomHeadersFromScanResults(outputDir)
	
	// Process each URL
	var allResults paramsmapper.Results
	allResults.Params = []string{}
	allResults.FormParams = []string{}
	allResults.TotalRequests = 0
	
	for i, url := range urls {
		// Check for stop signal before processing each URL
		stopFile := filepath.Join(outputDir, "stop_fuzzing")
		if _, err := os.Stat(stopFile); err == nil {
			log.Printf("DEBUG: Stop signal detected, aborting POST parameter fuzzing")
			// Write aborted progress
			s.writeProgressFile(outputDir, "post_progress.json", paramsmapper.ProgressInfo{
				Current:    i,
				Total:      len(urls),
				Percentage: (i * 100) / len(urls),
				Stage:      "aborted",
				Message:    "Fuzzing stopped by user",
				Discovered: len(allResults.Params),
			})
			return
		}
		
		request := paramsmapper.Request{
			URL:         url,
			Method:      "POST",
			ContentType: "form",
			Timeout:     10,
			Headers:     customHeaders,
		}
		
		// Create URL-based progress callback
		urlIndex := i + 1
		totalUrls := len(urls)
		progressCallback := func(progress paramsmapper.ProgressInfo) {
			// Calculate URL-based progress
			urlProgress := (urlIndex - 1) * 100 / totalUrls
			paramProgress := progress.Percentage / totalUrls
			totalProgress := urlProgress + paramProgress
			
			// Update progress info with URL-based calculation
			urlBasedProgress := paramsmapper.ProgressInfo{
				Current:    urlIndex,
				Total:      totalUrls,
				Percentage: totalProgress,
				Stage:      progress.Stage,
				Message:    fmt.Sprintf("Processing URL %d/%d: %s", urlIndex, totalUrls, progress.Message),
				Discovered: progress.Discovered,
			}
			s.writeProgressFile(outputDir, "post_progress.json", urlBasedProgress)
		}
		
        if chunkSize <= 0 {
            chunkSize = 500
        }
        results := paramsmapper.DiscoverParamsWithProgress(request, params, chunkSize, progressCallback)
		
		// Merge results
		allResults.Params = append(allResults.Params, results.Params...)
		allResults.FormParams = append(allResults.FormParams, results.FormParams...)
		allResults.TotalRequests += results.TotalRequests
	}
	
	// Remove duplicates
	allResults.Params = s.removeDuplicates(allResults.Params)
	allResults.FormParams = s.removeDuplicates(allResults.FormParams)
	
	// Save report
	paramsmapper.SaveReport(reportFile, allResults)
	log.Printf("Paramsmapper POST completed successfully. Found %d parameters, %d form parameters", 
		len(allResults.Params), len(allResults.FormParams))
}

// runParamsmapperForPOSTWithContext runs paramsmapper for POST requests with context cancellation
func (s *Service) runParamsmapperForPOSTWithContext(ctx context.Context, urlsFile, wordlistFile, outputDir string, chunkSize int) {
	log.Printf("Running paramsmapper for POST requests with context cancellation")
	
	reportFile := filepath.Join(outputDir, "post_report.json")
	
	// Load URLs from file
	urls, err := s.loadURLsFromFile(urlsFile)
	if err != nil {
		log.Printf("Error loading URLs from file: %v", err)
		return
	}
	
	// Load wordlist
	params := paramsmapper.LoadWordlist(wordlistFile)
	
	// Get custom headers
	customHeaders := s.getCustomHeadersFromScanResults(outputDir)
	
	// Process each URL
	var allResults paramsmapper.Results
	allResults.Params = []string{}
	allResults.FormParams = []string{}
	allResults.TotalRequests = 0
	
	for i, url := range urls {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			log.Printf("DEBUG: Context cancelled, aborting POST parameter fuzzing")
			// Write aborted progress
			s.writeProgressFile(outputDir, "post_progress.json", paramsmapper.ProgressInfo{
				Current:    i,
				Total:      len(urls),
				Percentage: (i * 100) / len(urls),
				Stage:      "aborted",
				Message:    "Fuzzing stopped by user",
				Discovered: len(allResults.Params),
			})
			return
		default:
			// Continue processing
		}
		
		request := paramsmapper.Request{
			URL:         url,
			Method:      "POST",
			ContentType: "form",
			Timeout:     10,
			Headers:     customHeaders,
		}
		
		// Create URL-based progress callback
		urlIndex := i + 1
		totalUrls := len(urls)
		progressCallback := func(progress paramsmapper.ProgressInfo) {
			// Check for cancellation in progress callback
			select {
			case <-ctx.Done():
				return // Don't update progress if cancelled
			default:
				// Calculate URL-based progress
				urlProgress := (urlIndex - 1) * 100 / totalUrls
				paramProgress := progress.Percentage / totalUrls
				totalProgress := urlProgress + paramProgress
				
				// Update progress info with URL-based calculation
				urlBasedProgress := paramsmapper.ProgressInfo{
					Current:    urlIndex,
					Total:      totalUrls,
					Percentage: totalProgress,
					Stage:      progress.Stage,
					Message:    fmt.Sprintf("Processing URL %d/%d: %s", urlIndex, totalUrls, progress.Message),
					Discovered: progress.Discovered,
				}
				s.writeProgressFile(outputDir, "post_progress.json", urlBasedProgress)
			}
		}
		
        // Run paramsmapper with progress callback
        if chunkSize <= 0 { chunkSize = 500 }
        result := paramsmapper.DiscoverParamsWithProgress(request, params, chunkSize, progressCallback)
		
		// Check for cancellation after paramsmapper completes
		select {
		case <-ctx.Done():
			log.Printf("DEBUG: Context cancelled after paramsmapper, aborting POST parameter fuzzing")
			// Write aborted progress
			s.writeProgressFile(outputDir, "post_progress.json", paramsmapper.ProgressInfo{
				Current:    i + 1,
				Total:      len(urls),
				Percentage: ((i + 1) * 100) / len(urls),
				Stage:      "aborted",
				Message:    "Fuzzing stopped by user",
				Discovered: len(allResults.Params),
			})
			return
		default:
			// Continue processing
		}
		
		// Merge results
		allResults.Params = append(allResults.Params, result.Params...)
		allResults.FormParams = append(allResults.FormParams, result.FormParams...)
		allResults.TotalRequests += result.TotalRequests
		
		// Set request info if not already set
		if allResults.Request.URL == "" {
			allResults.Request = result.Request
		}
	}
	
	// Remove duplicates
	allResults.Params = s.removeDuplicates(allResults.Params)
	allResults.FormParams = s.removeDuplicates(allResults.FormParams)
	
	// Save report
	paramsmapper.SaveReport(reportFile, allResults)
	log.Printf("Paramsmapper POST completed successfully. Found %d parameters, %d form parameters", 
		len(allResults.Params), len(allResults.FormParams))
}

// loadURLsFromFile loads URLs from a text file
func (s *Service) loadURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}

	return urls, scanner.Err()
}

// removeDuplicates removes duplicate strings from a slice
func (s *Service) removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

// convertResultsToScanningData converts database results to ScanningData format
func (s *Service) convertResultsToScanningData(results []database.ScanResult) *scanningData.ScanningData {
	scanData := &scanningData.ScanningData{
		GETEndpoints:  []scanningData.EndpointData{},
		POSTEndpoints: []scanningData.EndpointData{},
		JSEndpoints:   []scanningData.EndpointData{},
	}
	
	for _, result := range results {
		// Convert map[string]interface{} to map[string]string
		parameters := make(map[string]string)
		if result.Parameters != nil {
			for k, v := range result.Parameters {
				if str, ok := v.(string); ok {
					parameters[k] = str
				} else {
					parameters[k] = fmt.Sprintf("%v", v)
				}
			}
		}
		
		formData := make(map[string]string)
		if result.FormData != nil {
			for k, v := range result.FormData {
				if str, ok := v.(string); ok {
					formData[k] = str
				} else {
					formData[k] = fmt.Sprintf("%v", v)
				}
			}
		}
		
		headers := make(map[string]string)
		if result.Headers != nil {
			for k, v := range result.Headers {
				if str, ok := v.(string); ok {
					headers[k] = str
				} else {
					headers[k] = fmt.Sprintf("%v", v)
				}
			}
		}
		
		endpoint := scanningData.EndpointData{
			URL:         result.URL,
			Method:      result.Method,
			Parameters:  parameters,
			FormData:    formData,
			Headers:     headers,
			Description: result.Description,
		}
		
		switch result.EndpointType {
		case "get":
			endpoint.Type = "get"
			scanData.GETEndpoints = append(scanData.GETEndpoints, endpoint)
		case "post":
			endpoint.Type = "post"
			scanData.POSTEndpoints = append(scanData.POSTEndpoints, endpoint)
		case "js_api":
			endpoint.Type = "js_api"
			scanData.JSEndpoints = append(scanData.JSEndpoints, endpoint)
		}
	}
	
	// Update summary
	scanData.Summary.GETCount = len(scanData.GETEndpoints)
	scanData.Summary.POSTCount = len(scanData.POSTEndpoints)
	scanData.Summary.JSCount = len(scanData.JSEndpoints)
	scanData.Summary.TotalEndpoints = scanData.Summary.GETCount + scanData.Summary.POSTCount + scanData.Summary.JSCount
	
	return scanData
}

// decodeHTMLEntitiesInMap recursively decodes HTML entities in map values
func decodeHTMLEntitiesInMap(data map[string]interface{}) map[string]interface{} {
	if data == nil {
		return data
	}
	
	decoded := make(map[string]interface{})
	for key, value := range data {
		// Decode the key
		decodedKey := html.UnescapeString(key)
		
		// Decode the value based on its type
		switch v := value.(type) {
		case string:
			decoded[decodedKey] = html.UnescapeString(v)
		case map[string]interface{}:
			decoded[decodedKey] = decodeHTMLEntitiesInMap(v)
		case []interface{}:
			decoded[decodedKey] = decodeHTMLEntitiesInSlice(v)
		default:
			decoded[decodedKey] = v
		}
	}
	return decoded
}

// decodeHTMLEntitiesInSlice recursively decodes HTML entities in slice values
func decodeHTMLEntitiesInSlice(data []interface{}) []interface{} {
	if data == nil {
		return data
	}
	
	decoded := make([]interface{}, len(data))
	for i, value := range data {
		switch v := value.(type) {
		case string:
			decoded[i] = html.UnescapeString(v)
		case map[string]interface{}:
			decoded[i] = decodeHTMLEntitiesInMap(v)
		case []interface{}:
			decoded[i] = decodeHTMLEntitiesInSlice(v)
		default:
			decoded[i] = v
		}
	}
	return decoded
}

// HiddenUrlsData represents the structure for hidden URLs
type HiddenUrlsData struct {
	GETUrls  []map[string]interface{} `json:"get_urls"`
	POSTUrls []map[string]interface{} `json:"post_urls"`
}

// GetHiddenUrlsFromReports retrieves hidden URLs from paramsmapper reports
func (s *Service) GetHiddenUrlsFromReports(scanUUID string, userID int) (*HiddenUrlsData, error) {
	log.Printf("Getting hidden URLs from reports for scan %s", scanUUID)
	
	// Verify scan exists and user has access (admin can access any scan)
	// Check if user is admin by getting user from database
	user, err := s.GetUserByID(userID)
	if err != nil {
		return nil, err
	}
	if user.Role == "admin" {
		// Admin can access any scan
		_, err := s.GetScanByUUIDForAdmin(scanUUID)
		if err != nil {
			return nil, err
		}
	} else {
		// Regular user can only access their own scans
		_, err := s.GetScanByUUID(scanUUID, userID)
		if err != nil {
			return nil, err
		}
	}
	
	// Create scan directory path using UUID
	scanDir := filepath.Join("data", "scans", scanUUID)
	
	hiddenUrls := &HiddenUrlsData{
		GETUrls:  []map[string]interface{}{},
		POSTUrls: []map[string]interface{}{},
	}
	
	// Read GET report
	getReportFile := filepath.Join(scanDir, "get_report.json")
	if _, err := os.Stat(getReportFile); err == nil {
		getUrls, err := s.parseParamsmapperReport(getReportFile)
		if err != nil {
			log.Printf("Error parsing GET report: %v", err)
		} else {
			hiddenUrls.GETUrls = getUrls
		}
	}
	
	// Read POST report
	postReportFile := filepath.Join(scanDir, "post_report.json")
	if _, err := os.Stat(postReportFile); err == nil {
		postUrls, err := s.parseParamsmapperReport(postReportFile)
		if err != nil {
			log.Printf("Error parsing POST report: %v", err)
		} else {
			hiddenUrls.POSTUrls = postUrls
		}
	}
	
	log.Printf("Found %d GET hidden URLs and %d POST hidden URLs", len(hiddenUrls.GETUrls), len(hiddenUrls.POSTUrls))
	return hiddenUrls, nil
}

// GetFuzzingProgress retrieves the current fuzzing progress
func (s *Service) GetFuzzingProgress(scanUUID string, userID int) (map[string]interface{}, error) {
	log.Printf("DEBUG: GetFuzzingProgress called for scan %s, user %d", scanUUID, userID)
	
	// Verify scan exists and user has access (admin can access any scan)
	// Check if user is admin by getting user from database
	user, err := s.GetUserByID(userID)
	if err != nil {
		return nil, err
	}
	if user.Role == "admin" {
		// Admin can access any scan
		_, err := s.GetScanByUUIDForAdmin(scanUUID)
		if err != nil {
			log.Printf("DEBUG: GetFuzzingProgress - scan not found for admin: %v", err)
			return nil, err
		}
	} else {
		// Regular user can only access their own scans
		_, err := s.GetScanByUUID(scanUUID, userID)
		if err != nil {
			log.Printf("DEBUG: GetFuzzingProgress - scan not found for user: %v", err)
			return nil, err
		}
	}
	
	// Create scan directory path using UUID
	scanDir := filepath.Join("data", "scans", scanUUID)
	log.Printf("DEBUG: GetFuzzingProgress - checking scan directory: %s", scanDir)
	
	// Try to read GET progress first
	getProgressFile := filepath.Join(scanDir, "get_progress.json")
	log.Printf("DEBUG: GetFuzzingProgress - checking GET progress file: %s", getProgressFile)
	if _, err := os.Stat(getProgressFile); err == nil {
		log.Printf("DEBUG: GetFuzzingProgress - GET progress file exists, reading...")
		content, err := os.ReadFile(getProgressFile)
		if err != nil {
			log.Printf("DEBUG: GetFuzzingProgress - error reading GET progress file: %v", err)
			return nil, err
		}
		
		var progress map[string]interface{}
		err = json.Unmarshal(content, &progress)
		if err != nil {
			log.Printf("DEBUG: GetFuzzingProgress - error parsing GET progress file: %v", err)
			return nil, err
		}
		
		// Check if this is an old progress file from before server restart
		// If the process isn't in the running map, check if it was completed
		s.fuzzingMutex.RLock()
		_, isRunning := s.runningFuzzing[scanUUID]
		s.fuzzingMutex.RUnlock()
		
		if !isRunning {
			// Check if the progress shows completion
			if stage, ok := progress["stage"].(string); ok && (stage == "completed" || stage == "aborted") {
				log.Printf("DEBUG: GetFuzzingProgress - progress file shows %s stage, returning completed progress", stage)
				return progress, nil
			}
			
			log.Printf("DEBUG: GetFuzzingProgress - progress file exists but process not running (server restart), returning not_started")
			return map[string]interface{}{
				"current":    0,
				"total":      0,
				"percentage": 0,
				"stage":      "not_started",
				"message":    "Fuzzing not started",
				"discovered": 0,
				"timestamp":  time.Now().Unix(),
			}, nil
		}
		
		log.Printf("DEBUG: GetFuzzingProgress - returning GET progress: %+v", progress)
		return progress, nil
	} else {
		log.Printf("DEBUG: GetFuzzingProgress - GET progress file does not exist: %v", err)
	}
	
	// Try POST progress if GET doesn't exist
	postProgressFile := filepath.Join(scanDir, "post_progress.json")
	log.Printf("DEBUG: GetFuzzingProgress - checking POST progress file: %s", postProgressFile)
	if _, err := os.Stat(postProgressFile); err == nil {
		log.Printf("DEBUG: GetFuzzingProgress - POST progress file exists, reading...")
		content, err := os.ReadFile(postProgressFile)
		if err != nil {
			log.Printf("DEBUG: GetFuzzingProgress - error reading POST progress file: %v", err)
			return nil, err
		}
		
		var progress map[string]interface{}
		err = json.Unmarshal(content, &progress)
		if err != nil {
			log.Printf("DEBUG: GetFuzzingProgress - error parsing POST progress file: %v", err)
			return nil, err
		}
		
		// Check if this is an old progress file from before server restart
		// If the process isn't in the running map, check if it was completed
		s.fuzzingMutex.RLock()
		_, isRunning := s.runningFuzzing[scanUUID]
		s.fuzzingMutex.RUnlock()
		
		if !isRunning {
			// Check if the progress shows completion
			if stage, ok := progress["stage"].(string); ok && (stage == "completed" || stage == "aborted") {
				log.Printf("DEBUG: GetFuzzingProgress - POST progress file shows %s stage, returning completed progress", stage)
				return progress, nil
			}
			
			log.Printf("DEBUG: GetFuzzingProgress - POST progress file exists but process not running (server restart), returning not_started")
			return map[string]interface{}{
				"current":    0,
				"total":      0,
				"percentage": 0,
				"stage":      "not_started",
				"message":    "Fuzzing not started",
				"discovered": 0,
				"timestamp":  time.Now().Unix(),
			}, nil
		}
		
		log.Printf("DEBUG: GetFuzzingProgress - returning POST progress: %+v", progress)
		return progress, nil
	} else {
		log.Printf("DEBUG: GetFuzzingProgress - POST progress file does not exist: %v", err)
	}
	
	// No progress file found - return default
	log.Printf("DEBUG: GetFuzzingProgress - no progress files found, returning default")
	return map[string]interface{}{
		"current":    0,
		"total":      0,
		"percentage": 0,
		"stage":      "not_started",
		"message":    "Fuzzing not started",
		"discovered": 0,
		"timestamp":  time.Now().Unix(),
	}, nil
}

// StopParameterFuzzing stops the parameter fuzzing process
func (s *Service) StopParameterFuzzing(scanUUID string, userID int) error {
	log.Printf("DEBUG: StopParameterFuzzing called for scan %s, user %d", scanUUID, userID)
	
	// Verify scan exists and user has access (admin can access any scan)
	// Check if user is admin by getting user from database
	user, err := s.GetUserByID(userID)
	if err != nil {
		return err
	}
	if user.Role == "admin" {
		// Admin can access any scan
		_, err := s.GetScanByUUIDForAdmin(scanUUID)
		if err != nil {
			log.Printf("DEBUG: StopParameterFuzzing - scan not found for admin: %v", err)
			return err
		}
	} else {
		// Regular user can only access their own scans
		_, err := s.GetScanByUUID(scanUUID, userID)
		if err != nil {
			log.Printf("DEBUG: StopParameterFuzzing - scan not found for user: %v", err)
			return err
		}
	}
	
	// Cancel the running fuzzing process
	s.fuzzingMutex.Lock()
	cancel, exists := s.runningFuzzing[scanUUID]
	s.fuzzingMutex.Unlock()
	
	if exists {
		// Cancel the context if process is in running map
		cancel()
		log.Printf("DEBUG: StopParameterFuzzing - cancellation signal sent for scan %s", scanUUID)
	} else {
		log.Printf("DEBUG: StopParameterFuzzing - no running fuzzing process found in map for scan %s (likely server restart)", scanUUID)
	}
	
	// Always create a stop signal file (works for both running processes and server restart scenarios)
	scanDir := filepath.Join("data", "scans", scanUUID)
	stopFile := filepath.Join(scanDir, "stop_fuzzing")
	err = os.WriteFile(stopFile, []byte("stop"), 0644)
	if err != nil {
		log.Printf("DEBUG: StopParameterFuzzing - error creating stop file: %v", err)
		return fmt.Errorf("failed to create stop signal: %v", err)
	}
	
	log.Printf("DEBUG: StopParameterFuzzing - stop signal created successfully")
	return nil
}

// parseParamsmapperReport parses a paramsmapper JSON report
func (s *Service) parseParamsmapperReport(reportFile string) ([]map[string]interface{}, error) {
	content, err := os.ReadFile(reportFile)
	if err != nil {
		return nil, err
	}
	
	var report map[string]interface{}
	err = json.Unmarshal(content, &report)
	if err != nil {
		return nil, err
	}
	
	log.Printf("Parsing paramsmapper report: %s", reportFile)
	
	// Parse paramsmapper specific format
	var urls []map[string]interface{}
	
	// Get the base URL from the request
	baseURL := ""
	if request, ok := report["request"].(map[string]interface{}); ok {
		if url, ok := request["url"].(string); ok {
			baseURL = url
		}
	}
	
	// Get discovered parameters
	var discoveredParams []string
	if params, ok := report["params"].([]interface{}); ok {
		for _, param := range params {
			if paramStr, ok := param.(string); ok {
				discoveredParams = append(discoveredParams, paramStr)
			}
		}
	}
	
	// Get form parameters
	var formParams []string
	if formParamsData, ok := report["form_params"].([]interface{}); ok && formParamsData != nil {
		for _, param := range formParamsData {
			if paramStr, ok := param.(string); ok {
				formParams = append(formParams, paramStr)
			}
		}
	}
	
    // Derive scan directory from report file path to load headers
    scanDirPath := filepath.Dir(reportFile)

    // Create hidden URLs for discovered parameters
	if len(discoveredParams) > 0 && baseURL != "" {
		// Create URL with discovered parameters
		hiddenURL := s.createHiddenURL(baseURL, discoveredParams, "cybertronishere")
		
		// Detect which parameters are actually reflecting
        headers := s.getCustomHeadersFromScanResults(scanDirPath)
        reflectedParams, err := s.detectReflectedParameters(baseURL, discoveredParams, headers)
		if err != nil {
			log.Printf("DEBUG: Error detecting reflected parameters: %v", err)
			reflectedParams = []string{} // Default to empty if detection fails
		}
		
		urlData := map[string]interface{}{
			"url":         hiddenURL,
			"status":      "200", // Assume successful discovery
			"source":      "paramsmapper",
			"parameters":  discoveredParams,
			"reflected_parameters": reflectedParams,
			"total_requests": report["total_requests"],
			"method":      "GET",
		}
		
		log.Printf("DEBUG: Created hidden URL with %d parameters: %v, %d reflecting: %v", 
			len(discoveredParams), discoveredParams, len(reflectedParams), reflectedParams)
		
		urls = append(urls, urlData)
	}
	
    // Handle form parameters if any
	if len(formParams) > 0 && baseURL != "" {
		// For POST requests, we might want to show the URL with form data
		hiddenURL := s.createHiddenURL(baseURL, formParams, "cybertronishere")
		
		// Detect which form parameters are actually reflecting
        headers := s.getCustomHeadersFromScanResults(scanDirPath)
        reflectedFormParams, err := s.detectReflectedParameters(baseURL, formParams, headers)
		if err != nil {
			log.Printf("DEBUG: Error detecting reflected form parameters: %v", err)
			reflectedFormParams = []string{} // Default to empty if detection fails
		}
		
		urlData := map[string]interface{}{
			"url":         hiddenURL,
			"status":      "200",
			"source":      "paramsmapper",
			"parameters":  formParams,
			"reflected_parameters": reflectedFormParams,
			"total_requests": report["total_requests"],
			"method":      "POST",
		}
		
		log.Printf("DEBUG: Created form URL with %d parameters: %v, %d reflecting: %v", 
			len(formParams), formParams, len(reflectedFormParams), reflectedFormParams)
		
		urls = append(urls, urlData)
	}
	
	log.Printf("Parsed %d hidden URLs from report", len(urls))
	return urls, nil
}

// createHiddenURL creates a URL with discovered parameters
func (s *Service) createHiddenURL(baseURL string, parameters []string, value string) string {
	if len(parameters) == 0 {
		return baseURL
	}
	
	// Parse the base URL
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	
	// Add parameters to the URL
	query := u.Query()
    for _, param := range parameters {
        // Use a stable, readable token per parameter in the URL preview
        query.Set(param, s.generateParamScopedToken(param))
    }
	u.RawQuery = query.Encode()
	
	return u.String()
}

// detectReflectedParameters checks which parameters are reflected in the response
func (s *Service) detectReflectedParameters(baseURL string, parameters []string, headers map[string]string) ([]string, error) {
	if len(parameters) == 0 {
		return []string{}, nil
	}
	
    var reflectedParams []string
	
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
    // Test each parameter individually with a param-scoped token
    for _, param := range parameters {
        // Parse fresh base each iteration to avoid carrying prior params
        u, err := url.Parse(baseURL)
        if err != nil {
            return nil, fmt.Errorf("failed to parse URL: %v", err)
        }
        // Generate a token unique to this parameter
        token := s.generateParamScopedToken(param)
        values := url.Values{}
        // Keep other discovered parameters present with neutral value to satisfy endpoints
        for _, p := range parameters {
            if p == param {
                values.Set(p, token)
            } else {
                // neutral values that typically keep endpoint happy
                // avoid interfering pairs; set to empty to minimize changes
                values.Set(p, "")
            }
        }
        u.RawQuery = values.Encode()
        testURL := u.String()
		
		log.Printf("DEBUG: Testing reflection for parameter '%s' with URL: %s", param, testURL)
		
        // Make the request
        req, err := http.NewRequest(http.MethodGet, testURL, nil)
        if err != nil {
            return nil, err
        }
        // include headers (cookies/auth) to match scan context
        for k, v := range headers {
            req.Header.Set(k, v)
        }
        resp, err := client.Do(req)
		if err != nil {
			log.Printf("DEBUG: Failed to make request for parameter '%s': %v", param, err)
			continue
		}
		
		// Read the response body
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("DEBUG: Failed to read response body for parameter '%s': %v", param, err)
			continue
		}
		
		// Check if the test value appears in the response
        if strings.Contains(string(body), token) {
			log.Printf("DEBUG: Parameter '%s' is reflecting in response", param)
			reflectedParams = append(reflectedParams, param)
		} else {
			log.Printf("DEBUG: Parameter '%s' is NOT reflecting in response", param)
		}
	}
	
	log.Printf("DEBUG: Reflection detection complete. %d/%d parameters are reflecting: %v", 
		len(reflectedParams), len(parameters), reflectedParams)
	
	return reflectedParams, nil
}

// generateParamScopedToken creates a predictable token embedding the parameter name
// to attribute reflections and minimize false positives in previews and checks.
func (s *Service) generateParamScopedToken(param string) string {
    sanitized := param
    if sanitized == "" {
        sanitized = "p"
    }
    if len(sanitized) > 32 {
        sanitized = sanitized[:32]
    }
    // simple random suffix for uniqueness per run
    const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    var b strings.Builder
    for i := 0; i < 8; i++ {
        b.WriteByte(letters[int(time.Now().UnixNano()+int64(i))%len(letters)])
    }
    // Alphanumeric-only token to avoid strict validation failures
    return "VIDU" + sanitized + b.String()
}

// writeProgressFile writes progress information to a JSON file
func (s *Service) writeProgressFile(scanDir, filename string, progress paramsmapper.ProgressInfo) {
	progressFile := filepath.Join(scanDir, filename)
	log.Printf("DEBUG: writeProgressFile called - file: %s, progress: %+v", progressFile, progress)
	
	// Add timestamp to progress info
	progressData := map[string]interface{}{
		"current":     progress.Current,
		"total":       progress.Total,
		"percentage":  progress.Percentage,
		"stage":       progress.Stage,
		"message":     progress.Message,
		"discovered":  progress.Discovered,
		"timestamp":   time.Now().Unix(),
	}
	
	jsonData, err := json.Marshal(progressData)
	if err != nil {
		log.Printf("Error marshalling progress data: %v", err)
		return
	}
	
	err = os.WriteFile(progressFile, jsonData, 0644)
	if err != nil {
		log.Printf("Error writing progress file %s: %v", progressFile, err)
		return
	}
	
	log.Printf("DEBUG: Progress file written successfully - %s: %d%% (%s)", progress.Stage, progress.Percentage, progress.Message)
}

// clearPreviousFuzzReports removes prior paramsmapper reports and progress files
// so a new fuzzing run produces clean results visible in the Hidden URLs tab.
func (s *Service) clearPreviousFuzzReports(scanUUID string) error {
    scanDir := filepath.Join("data", "scans", scanUUID)
    targets := []string{
        filepath.Join(scanDir, "get_report.json"),
        filepath.Join(scanDir, "post_report.json"),
        filepath.Join(scanDir, "get_progress.json"),
        filepath.Join(scanDir, "post_progress.json"),
    }
    var firstErr error
    for _, f := range targets {
        if err := os.Remove(f); err != nil {
            if !os.IsNotExist(err) && firstErr == nil {
                firstErr = err
            }
        }
    }
    return firstErr
}

// getCustomHeadersFromScanResults extracts custom headers from scan results
func (s *Service) getCustomHeadersFromScanResults(scanDir string) map[string]string {
	// Extract scan UUID from the scan directory path
	// scanDir format: "data/scans/{scanUUID}"
	parts := strings.Split(scanDir, string(filepath.Separator))
	if len(parts) < 3 {
		log.Printf("DEBUG: Invalid scan directory path: %s", scanDir)
		return make(map[string]string)
	}
	scanUUID := parts[len(parts)-1]
	
	log.Printf("DEBUG: Getting custom headers for scan UUID: %s", scanUUID)
	
	// Get the scan ID from UUID
	var scanID int
	err := s.db.QueryRow("SELECT id FROM scans WHERE scan_uuid = ?", scanUUID).Scan(&scanID)
	if err != nil {
		log.Printf("DEBUG: Error getting scan ID for UUID %s: %v", scanUUID, err)
		return make(map[string]string)
	}
	
	// Get headers from the first scan result (they should be the same for all results)
	var headersJSON sql.NullString
	err = s.db.QueryRow(`
		SELECT headers FROM scan_results 
		WHERE scan_id = ? AND headers IS NOT NULL AND headers != '' 
		LIMIT 1`, scanID).Scan(&headersJSON)
	
	if err != nil {
		log.Printf("DEBUG: No headers found for scan ID %d: %v", scanID, err)
		return make(map[string]string)
	}
	
	if !headersJSON.Valid || headersJSON.String == "" {
		log.Printf("DEBUG: Headers field is empty for scan ID %d", scanID)
		return make(map[string]string)
	}
	
	// Parse headers JSON
	var headers map[string]interface{}
	err = json.Unmarshal([]byte(headersJSON.String), &headers)
	if err != nil {
		log.Printf("DEBUG: Error parsing headers JSON for scan ID %d: %v", scanID, err)
		return make(map[string]string)
	}
	
	// Convert to map[string]string
	customHeaders := make(map[string]string)
	for k, v := range headers {
		if str, ok := v.(string); ok {
			customHeaders[k] = str
		} else {
			customHeaders[k] = fmt.Sprintf("%v", v)
		}
	}
	
	log.Printf("DEBUG: Retrieved %d custom headers for scan %s", len(customHeaders), scanUUID)
	return customHeaders
}

// saveHeadersToFile saves headers to a file in the format expected by paramsmapper
func (s *Service) saveHeadersToFile(headers map[string]string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	for headerName, headerValue := range headers {
		_, err = file.WriteString(fmt.Sprintf("%s: %s\n", headerName, headerValue))
		if err != nil {
			return err
		}
	}
	
	return nil
}

// extractUrlsFromRawReport extracts URLs from raw report content
func (s *Service) extractUrlsFromRawReport(content string) []map[string]interface{} {
	var urls []map[string]interface{}
	
	// Simple URL extraction - this can be enhanced based on actual paramsmapper output
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http") && (strings.Contains(line, "?") || strings.Contains(line, "&")) {
			urls = append(urls, map[string]interface{}{
				"url":    line,
				"status": "200", // Default status
				"source": "paramsmapper",
			})
		}
	}
	
	return urls
}

// updateScanStatus updates the scan status
func (s *Service) updateScanStatus(scanID int, status string, progress int) {
	now := time.Now()
	_, err := s.db.Exec(`
		UPDATE scans SET status = ?, progress = ?, completed_at = ? 
		WHERE id = ?`,
		status, progress, now, scanID)
	if err != nil {
		log.Printf("Error updating scan status: %v", err)
	}
}

// updateScanProgress updates the scan progress
func (s *Service) updateScanProgress(scanID int, progress int) {
	_, err := s.db.Exec(`UPDATE scans SET progress = ? WHERE id = ?`, progress, scanID)
	if err != nil {
		log.Printf("Error updating scan progress: %v", err)
	}
}

// GetScans retrieves scans for a user
func (s *Service) GetScans(userID int, limit, offset int) ([]database.Scan, error) {
	rows, err := s.db.Query(`
		SELECT id, scan_uuid, user_id, target_url, max_depth, max_pages, headers, status, progress, 
		       started_at, completed_at, created_at
		FROM scans 
		WHERE user_id = ? 
		ORDER BY created_at DESC 
		LIMIT ? OFFSET ?`,
		userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []database.Scan
	for rows.Next() {
		var scan database.Scan
		var headersJSON sql.NullString
		
		err := rows.Scan(
			&scan.ID, &scan.ScanUUID, &scan.UserID, &scan.TargetURL, &scan.MaxDepth, &scan.MaxPages, &headersJSON,
			&scan.Status, &scan.Progress, &scan.StartedAt, &scan.CompletedAt, &scan.CreatedAt)
		if err != nil {
			return nil, err
		}
		
		// Parse headers JSON
		if headersJSON.Valid && headersJSON.String != "" {
			err = json.Unmarshal([]byte(headersJSON.String), &scan.Headers)
			if err != nil {
				log.Printf("Error parsing headers JSON for scan %d: %v", scan.ID, err)
				scan.Headers = make(map[string]interface{})
			}
		} else {
			scan.Headers = make(map[string]interface{})
		}
		
		scans = append(scans, scan)
	}

	return scans, nil
}

// GetScan retrieves a specific scan
func (s *Service) GetScan(scanID, userID int) (*database.Scan, error) {
	scan := &database.Scan{}
	var headersJSON sql.NullString
	
	err := s.db.QueryRow(`
		SELECT id, user_id, target_url, max_depth, max_pages, headers, status, progress, 
		       started_at, completed_at, created_at
		FROM scans 
		WHERE id = ? AND user_id = ?`,
		scanID, userID).Scan(
		&scan.ID, &scan.UserID, &scan.TargetURL, &scan.MaxDepth, &scan.MaxPages, &headersJSON,
		&scan.Status, &scan.Progress, &scan.StartedAt, &scan.CompletedAt, &scan.CreatedAt)
	if err != nil {
		return nil, err
	}
	
	// Parse headers JSON
	if headersJSON.Valid && headersJSON.String != "" {
		err = json.Unmarshal([]byte(headersJSON.String), &scan.Headers)
		if err != nil {
			log.Printf("Error parsing headers JSON for scan %d: %v", scanID, err)
			scan.Headers = make(map[string]interface{})
		}
	} else {
		scan.Headers = make(map[string]interface{})
	}
	
	return scan, nil
}

// GetScanResults retrieves results for a specific scan
func (s *Service) GetScanResults(scanID, userID int) ([]database.ScanResult, error) {
	// Verify scan belongs to user
	_, err := s.GetScan(scanID, userID)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Query(`
		SELECT id, scan_id, endpoint_type, url, method, parameters, form_data, headers, description, created_at
		FROM scan_results 
		WHERE scan_id = ? 
		ORDER BY created_at DESC`,
		scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []database.ScanResult
	for rows.Next() {
		var result database.ScanResult
		var paramsJSON, formDataJSON, headersJSON sql.NullString
		
		err := rows.Scan(
			&result.ID, &result.ScanID, &result.EndpointType, &result.URL, &result.Method,
			&paramsJSON, &formDataJSON, &headersJSON, &result.Description, &result.CreatedAt)
		if err != nil {
			return nil, err
		}

		// Parse JSON fields, handling NULL values
		if paramsJSON.Valid {
			json.Unmarshal([]byte(paramsJSON.String), &result.Parameters)
			// Decode HTML entities in parameter names and values
			result.Parameters = decodeHTMLEntitiesInMap(result.Parameters)
		} else {
			result.Parameters = make(map[string]interface{})
		}
		
		if formDataJSON.Valid {
			json.Unmarshal([]byte(formDataJSON.String), &result.FormData)
		} else {
			result.FormData = make(map[string]interface{})
		}
		
		if headersJSON.Valid {
			json.Unmarshal([]byte(headersJSON.String), &result.Headers)
		} else {
			result.Headers = make(map[string]interface{})
		}

		results = append(results, result)
	}

	return results, nil
}

// GetScanOwner returns the user ID who owns the scan with the given UUID
// This is used by the RequireResourceOwnership middleware
func (s *Service) GetScanOwner(scanUUID string) (int, error) {
	var userID int
	err := s.db.QueryRow("SELECT user_id FROM scans WHERE scan_uuid = ?", scanUUID).Scan(&userID)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

// CleanupOldScanDirectories removes old numeric scan directories that are no longer needed
func (s *Service) CleanupOldScanDirectories() error {
	scansDir := "data/scans"
	
	// Read all directories in the scans folder
	entries, err := os.ReadDir(scansDir)
	if err != nil {
		return fmt.Errorf("failed to read scans directory: %v", err)
	}
	
	var deletedCount int
	var errors []string
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		dirName := entry.Name()
		
		// Check if directory name is numeric (old format)
		if isNumeric(dirName) {
			dirPath := filepath.Join(scansDir, dirName)
			
			// Check if this numeric ID exists in the database
			scanID, err := strconv.Atoi(dirName)
			if err != nil {
				log.Printf("Warning: Could not parse directory name as number: %s", dirName)
				continue
			}
			
			// Check if scan exists in database
			exists, err := s.scanExistsInDatabase(scanID)
			if err != nil {
				log.Printf("Error checking if scan %d exists in database: %v", scanID, err)
				errors = append(errors, fmt.Sprintf("Error checking scan %d: %v", scanID, err))
				continue
			}
			
			if !exists {
				// Scan doesn't exist in database, safe to delete
				log.Printf("Deleting orphaned scan directory: %s", dirPath)
				err := os.RemoveAll(dirPath)
				if err != nil {
					log.Printf("Error deleting directory %s: %v", dirPath, err)
					errors = append(errors, fmt.Sprintf("Error deleting %s: %v", dirPath, err))
				} else {
					deletedCount++
					log.Printf("Successfully deleted old scan directory: %s", dirPath)
				}
			} else {
				log.Printf("Keeping directory %s - scan exists in database", dirPath)
			}
		}
	}
	
	log.Printf("Cleanup completed. Deleted %d old scan directories.", deletedCount)
	if len(errors) > 0 {
		log.Printf("Errors encountered during cleanup: %v", errors)
		return fmt.Errorf("cleanup completed with %d errors", len(errors))
	}
	
	return nil
}

// isNumeric checks if a string contains only numeric characters
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, char := range s {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

// scanExistsInDatabase checks if a scan with the given ID exists in the database
func (s *Service) scanExistsInDatabase(scanID int) (bool, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM scans WHERE id = ?", scanID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// CleanupOrphanedScanFiles removes scan directories that exist on disk but not in the database
func (s *Service) CleanupOrphanedScanFiles() error {
	scansDir := "data/scans"
	
	// Read all directories in the scans folder
	entries, err := os.ReadDir(scansDir)
	if err != nil {
		return fmt.Errorf("failed to read scans directory: %v", err)
	}
	
	var deletedCount int
	var errors []string
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		dirName := entry.Name()
		dirPath := filepath.Join(scansDir, dirName)
		
		// Check if this directory corresponds to a scan in the database
		exists, err := s.scanExistsByUUID(dirName)
		if err != nil {
			log.Printf("Error checking if scan directory %s exists in database: %v", dirName, err)
			errors = append(errors, fmt.Sprintf("Error checking directory %s: %v", dirName, err))
			continue
		}
		
		if !exists {
			// Directory doesn't correspond to any scan in database, safe to delete
			log.Printf("Deleting orphaned scan directory: %s", dirPath)
			err := os.RemoveAll(dirPath)
			if err != nil {
				log.Printf("Error deleting orphaned directory %s: %v", dirPath, err)
				errors = append(errors, fmt.Sprintf("Error deleting %s: %v", dirPath, err))
			} else {
				deletedCount++
				log.Printf("Successfully deleted orphaned scan directory: %s", dirPath)
			}
		}
	}
	
	log.Printf("Orphaned files cleanup completed. Deleted %d orphaned scan directories.", deletedCount)
	if len(errors) > 0 {
		log.Printf("Errors encountered during orphaned files cleanup: %v", errors)
		return fmt.Errorf("cleanup completed with %d errors", len(errors))
	}
	
	return nil
}

// DeleteAllScans deletes all scans from database and filesystem for a specific user
func (s *Service) DeleteAllScans(userID int) error {
	log.Printf("WARNING: DeleteAllScans called by user %d - this will delete ALL scans for this user!", userID)
	
	// Get all scans for the user
	scans, err := s.GetScans(userID, 1000, 0) // Get all scans for the user
	if err != nil {
		return fmt.Errorf("failed to get user scans: %v", err)
	}
	
	if len(scans) == 0 {
		log.Printf("No scans found for user %d", userID)
		return nil
	}
	
	log.Printf("Found %d scans to delete for user %d", len(scans), userID)
	
	var deletedCount int
	var errors []string
	
	// Delete each scan
	for _, scan := range scans {
		log.Printf("Deleting scan %d (UUID: %s) for user %d", scan.ID, scan.ScanUUID, userID)
		
		// Delete scan files
		scanDir := filepath.Join("data", "scans", scan.ScanUUID)
		err := os.RemoveAll(scanDir)
		if err != nil {
			log.Printf("Warning: Failed to delete scan directory %s: %v", scanDir, err)
			errors = append(errors, fmt.Sprintf("Failed to delete directory %s: %v", scanDir, err))
		} else {
			log.Printf("Successfully deleted scan directory: %s", scanDir)
		}
		
		// Delete from database
		_, err = s.db.Exec(`DELETE FROM scans WHERE id = ? AND user_id = ?`, scan.ID, userID)
		if err != nil {
			log.Printf("Error deleting scan %d from database: %v", scan.ID, err)
			errors = append(errors, fmt.Sprintf("Failed to delete scan %d from database: %v", scan.ID, err))
		} else {
			deletedCount++
			log.Printf("Successfully deleted scan %d from database", scan.ID)
		}
	}
	
	log.Printf("Bulk deletion completed. Deleted %d scans for user %d.", deletedCount, userID)
	if len(errors) > 0 {
		log.Printf("Errors encountered during bulk deletion: %v", errors)
		return fmt.Errorf("bulk deletion completed with %d errors", len(errors))
	}
	
	return nil
}

// DeleteAllScansForAllUsers deletes ALL scans from ALL users (EXTREMELY DANGEROUS!)
func (s *Service) DeleteAllScansForAllUsers() error {
	log.Printf("CRITICAL WARNING: DeleteAllScansForAllUsers called - this will delete ALL scans from ALL users!")
	
	// Get all scans
	rows, err := s.db.Query("SELECT id, scan_uuid FROM scans")
	if err != nil {
		return fmt.Errorf("failed to get all scans: %v", err)
	}
	defer rows.Close()
	
	var scans []struct {
		ID       int
		ScanUUID string
	}
	
	for rows.Next() {
		var scan struct {
			ID       int
			ScanUUID string
		}
		err := rows.Scan(&scan.ID, &scan.ScanUUID)
		if err != nil {
			log.Printf("Error scanning scan row: %v", err)
			continue
		}
		scans = append(scans, scan)
	}
	
	if len(scans) == 0 {
		log.Printf("No scans found in database")
		return nil
	}
	
	log.Printf("Found %d total scans to delete", len(scans))
	
	var deletedCount int
	var errors []string
	
	// Delete each scan
	for _, scan := range scans {
		log.Printf("Deleting scan %d (UUID: %s)", scan.ID, scan.ScanUUID)
		
		// Delete scan files
		scanDir := filepath.Join("data", "scans", scan.ScanUUID)
		err := os.RemoveAll(scanDir)
		if err != nil {
			log.Printf("Warning: Failed to delete scan directory %s: %v", scanDir, err)
			errors = append(errors, fmt.Sprintf("Failed to delete directory %s: %v", scanDir, err))
		} else {
			log.Printf("Successfully deleted scan directory: %s", scanDir)
		}
		
		// Delete from database
		_, err = s.db.Exec(`DELETE FROM scans WHERE id = ?`, scan.ID)
		if err != nil {
			log.Printf("Error deleting scan %d from database: %v", scan.ID, err)
			errors = append(errors, fmt.Sprintf("Failed to delete scan %d from database: %v", scan.ID, err))
		} else {
			deletedCount++
			log.Printf("Successfully deleted scan %d from database", scan.ID)
		}
	}
	
	log.Printf("CRITICAL: Bulk deletion completed. Deleted %d scans from ALL users.", deletedCount)
	if len(errors) > 0 {
		log.Printf("Errors encountered during bulk deletion: %v", errors)
		return fmt.Errorf("bulk deletion completed with %d errors", len(errors))
	}
	
	return nil
}

// GetAllUsers retrieves all users from the database (admin only)
func (s *Service) GetAllUsers() ([]database.User, error) {
	rows, err := s.db.Query(`
		SELECT id, username, email, role, created_at 
		FROM users 
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []database.User
	for rows.Next() {
		var user database.User
		err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.CreatedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// GetUserByID retrieves a user by ID
func (s *Service) GetUserByID(userID int) (*database.User, error) {
	user := &database.User{}
	err := s.db.QueryRow(`
		SELECT id, username, email, role, created_at, updated_at 
		FROM users WHERE id = ?`, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.Role, 
		&user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// PromoteUserToAdmin promotes a user to admin role
func (s *Service) PromoteUserToAdmin(userID int) error {
	log.Printf("Promoting user %d to admin role", userID)
	
	_, err := s.db.Exec("UPDATE users SET role = 'admin', updated_at = CURRENT_TIMESTAMP WHERE id = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to promote user to admin: %v", err)
	}
	
	log.Printf("Successfully promoted user %d to admin role", userID)
	return nil
}

// GetUserStats retrieves statistics for a specific user
func (s *Service) GetUserStats(userID int) (*database.DashboardStats, error) {
	log.Printf("DEBUG: GetUserStats called for user %d", userID)
	stats := &database.DashboardStats{}

	// Get scan counts
	log.Printf("DEBUG: Getting scan counts for user %d", userID)
	err := s.db.QueryRow(`
		SELECT 
			COUNT(*) as total_scans,
			COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as completed_scans,
			COALESCE(SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END), 0) as running_scans
		FROM scans WHERE user_id = ?`,
		userID).Scan(&stats.TotalScans, &stats.CompletedScans, &stats.RunningScans)
	if err != nil {
		log.Printf("DEBUG: Error getting scan counts: %v", err)
		return nil, err
	}
	log.Printf("DEBUG: Scan counts - Total: %d, Completed: %d, Running: %d", stats.TotalScans, stats.CompletedScans, stats.RunningScans)

	// Get total endpoints
	log.Printf("DEBUG: Getting total endpoints for user %d", userID)
	err = s.db.QueryRow(`
		SELECT COUNT(*) 
		FROM scan_results sr 
		JOIN scans s ON sr.scan_id = s.id 
		WHERE s.user_id = ?`,
		userID).Scan(&stats.TotalEndpoints)
	if err != nil {
		log.Printf("DEBUG: Error getting total endpoints: %v", err)
		return nil, err
	}
	log.Printf("DEBUG: Total endpoints: %d", stats.TotalEndpoints)

	// Get recent scans
	log.Printf("DEBUG: Getting recent scans for user %d", userID)
	recentScans, err := s.GetScans(userID, 5, 0)
	if err != nil {
		log.Printf("DEBUG: Error getting recent scans: %v", err)
		return nil, err
	}
	stats.RecentScans = recentScans
	log.Printf("DEBUG: Found %d recent scans", len(recentScans))

	log.Printf("DEBUG: GetUserStats completed successfully for user %d", userID)
	return stats, nil
}

// DeleteUser deletes a user and all their associated data
func (s *Service) DeleteUser(userID int) error {
	log.Printf("WARNING: DeleteUser called for user %d - this will delete the user and ALL their data!", userID)

	// Get all scans for the user first
	scans, err := s.GetScans(userID, 1000, 0) // Get all scans for the user
	if err != nil {
		return fmt.Errorf("failed to get user scans: %v", err)
	}

	// Delete all scan files for this user
	for _, scan := range scans {
		scanDir := filepath.Join("data", "scans", scan.ScanUUID)
		err := os.RemoveAll(scanDir)
		if err != nil {
			log.Printf("Warning: Failed to delete scan directory %s: %v", scanDir, err)
		} else {
			log.Printf("Successfully deleted scan directory: %s", scanDir)
		}
	}

	// Delete user from database (cascade will handle related records)
	_, err = s.db.Exec(`DELETE FROM users WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}

	log.Printf("Successfully deleted user %d and all associated data", userID)
	return nil
}

// DeleteUserScan deletes a specific scan for any user (admin function)
func (s *Service) DeleteUserScan(scanID int) error {
	// Get scan details first
	var scanUUID string
	var userID int
	err := s.db.QueryRow("SELECT scan_uuid, user_id FROM scans WHERE id = ?", scanID).Scan(&scanUUID, &userID)
	if err != nil {
		return fmt.Errorf("failed to get scan details: %v", err)
	}

	log.Printf("Admin deleting scan %d (UUID: %s) for user %d", scanID, scanUUID, userID)

	// Delete scan files
	scanDir := filepath.Join("data", "scans", scanUUID)
	err = os.RemoveAll(scanDir)
	if err != nil {
		log.Printf("Warning: Failed to delete scan directory %s: %v", scanDir, err)
	} else {
		log.Printf("Successfully deleted scan directory: %s", scanDir)
	}

	// Delete from database
	_, err = s.db.Exec(`DELETE FROM scans WHERE id = ?`, scanID)
	if err != nil {
		return fmt.Errorf("failed to delete scan from database: %v", err)
	}

	log.Printf("Successfully deleted scan %d for user %d", scanID, userID)
	return nil
}

// scanExistsByUUID checks if a scan with the given UUID exists in the database
func (s *Service) scanExistsByUUID(scanUUID string) (bool, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM scans WHERE scan_uuid = ?", scanUUID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// DeleteScan deletes a scan and its associated data
func (s *Service) DeleteScan(scanID, userID int) error {
	// Verify scan belongs to user and get scan details
	scan, err := s.GetScan(scanID, userID)
	if err != nil {
		return err
	}

	// Delete scan files using UUID
	scanDir := filepath.Join("data", "scans", scan.ScanUUID)
	log.Printf("Deleting scan files from directory: %s", scanDir)
	
	err = os.RemoveAll(scanDir)
	if err != nil {
		log.Printf("Warning: Failed to delete scan directory %s: %v", scanDir, err)
		// Continue with database deletion even if file deletion fails
	} else {
		log.Printf("Successfully deleted scan directory: %s", scanDir)
	}

	// Delete from database (cascade will handle related records)
	_, err = s.db.Exec(`DELETE FROM scans WHERE id = ? AND user_id = ?`, scanID, userID)
	if err != nil {
		log.Printf("Error deleting scan %d from database: %v", scanID, err)
		return err
	}
	
	log.Printf("Successfully deleted scan %d (UUID: %s) from database and filesystem", scanID, scan.ScanUUID)
	return nil
}

// GetDashboardStats retrieves dashboard statistics for a user
func (s *Service) GetDashboardStats(userID int) (*database.DashboardStats, error) {
	stats := &database.DashboardStats{}

	// Get scan counts
	err := s.db.QueryRow(`
		SELECT 
			COUNT(*) as total_scans,
			COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as completed_scans,
			COALESCE(SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END), 0) as running_scans
		FROM scans WHERE user_id = ?`,
		userID).Scan(&stats.TotalScans, &stats.CompletedScans, &stats.RunningScans)
	if err != nil {
		return nil, err
	}

	// Get total endpoints
	err = s.db.QueryRow(`
		SELECT COUNT(*) 
		FROM scan_results sr 
		JOIN scans s ON sr.scan_id = s.id 
		WHERE s.user_id = ?`,
		userID).Scan(&stats.TotalEndpoints)
	if err != nil {
		return nil, err
	}

	// Get recent scans
	recentScans, err := s.GetScans(userID, 5, 0)
	if err != nil {
		return nil, err
	}
	stats.RecentScans = recentScans

	// Compute YetToScan from domains.txt (non-empty lines) minus total scans
	// If domains.txt is missing, default to 0
	totalDomains := 0
	if content, err := os.ReadFile("domains.txt"); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, ln := range lines {
			if strings.TrimSpace(ln) != "" {
				totalDomains++
			}
		}
	}
	if totalDomains > stats.TotalScans {
		stats.YetToScan = totalDomains - stats.TotalScans
	} else {
		stats.YetToScan = 0
	}

    // Count vulnerabilities across ALL scans for this user by summing non-empty lines in xss.txt
    totalAxiom := 0
    rows, err := s.db.Query(`SELECT scan_uuid FROM scans WHERE user_id = ?`, userID)
    if err == nil {
        defer rows.Close()
        for rows.Next() {
            var uuid string
            if err := rows.Scan(&uuid); err != nil { continue }
            scanDir := filepath.Join("data", "scans", uuid)
            xssFile := filepath.Join(scanDir, "xss.txt")
            if content, err := os.ReadFile(xssFile); err == nil {
                lines := strings.Split(string(content), "\n")
                for _, ln := range lines {
                    if strings.TrimSpace(ln) != "" {
                        totalAxiom++
                    }
                }
            }
        }
    }
    stats.AxiomResults = totalAxiom

    return stats, nil
}

// RescanScan restarts a scan with new parameters, updating the existing scan
func (s *Service) RescanScan(scanID, userID int, req *ScanRequest) (*ScanResponse, error) {
	// First verify the scan exists and belongs to the user
	scan, err := s.GetScan(scanID, userID)
	if err != nil {
		return nil, err
	}

	log.Printf("Rescanning scan %d for user %d, target: %s", scanID, userID, scan.TargetURL)

	// Reset scan status and progress
	_, err = s.db.Exec(`
		UPDATE scans SET 
			status = 'pending', 
			progress = 0, 
			max_depth = ?, 
			max_pages = ?,
			started_at = NULL,
			completed_at = NULL
		WHERE id = ? AND user_id = ?`,
		req.MaxDepth, req.MaxPages, scanID, userID)
	if err != nil {
		log.Printf("Error resetting scan status: %v", err)
		return nil, err
	}

	// Delete existing scan results
	_, err = s.db.Exec(`DELETE FROM scan_results WHERE scan_id = ?`, scanID)
	if err != nil {
		log.Printf("Error deleting existing scan results: %v", err)
		return nil, err
	}

	// Delete existing scan files using UUID
	scanDir := filepath.Join("data", "scans", scan.ScanUUID)
	log.Printf("Deleting existing scan files from directory: %s", scanDir)
	
	err = os.RemoveAll(scanDir)
	if err != nil {
		log.Printf("Warning: Failed to delete existing scan directory %s: %v", scanDir, err)
		// Continue with rescan even if file deletion fails
	} else {
		log.Printf("Successfully deleted existing scan directory: %s", scanDir)
	}

	// Set the target URL in the request for the rescan
	req.TargetURL = scan.TargetURL
	
	// Use the original headers from the scan instead of new ones
	if scan.Headers != nil && len(scan.Headers) > 0 {
		// Convert scan.Headers (map[string]interface{}) to req.Headers (map[string]string)
		req.Headers = make(map[string]string)
		for k, v := range scan.Headers {
			if str, ok := v.(string); ok {
				req.Headers[k] = str
			} else {
				req.Headers[k] = fmt.Sprintf("%v", v)
			}
		}
		log.Printf("Rescan using original headers: %v", req.Headers)
	} else {
		log.Printf("Rescan: No original headers found, using new headers: %v", req.Headers)
	}
	
	log.Printf("Rescan request prepared - URL: %s, MaxDepth: %d, MaxPages: %d", req.TargetURL, req.MaxDepth, req.MaxPages)

	// Start the scan in a goroutine using the existing runScan method
	log.Printf("Starting rescan goroutine for scan %d", scanID)
	go s.runScan(scanID, scan.ScanUUID, req)

	return &ScanResponse{
		ScanID:  scanID,
		Status:  "pending",
		Message: "Rescan started successfully",
	}, nil
}

// GetScanByHost finds the most recent scan for a given URL (exact match)
func (s *Service) GetScanByHost(userID int, hostURL string) (*database.Scan, error) {
	scan := &database.Scan{}
	
	log.Printf("GetScanByHost called - UserID: %d, URL: %s", userID, hostURL)
	
	// Find the most recent scan for this exact URL (with or without trailing slash)
	// This handles cases where URLs might be stored with different formats
	// But we want exact path matching, not just host matching
	err := s.db.QueryRow(`
		SELECT id, scan_uuid, user_id, target_url, status, progress, created_at
		FROM scans 
		WHERE user_id = ? AND target_url = ?
		ORDER BY created_at DESC 
		LIMIT 1`,
		userID, hostURL).Scan(
		&scan.ID, &scan.ScanUUID, &scan.UserID, &scan.TargetURL, &scan.Status, 
		&scan.Progress, &scan.CreatedAt)
	
	if err != nil {
		log.Printf("GetScanByHost - No scan found for UserID: %d, URL: %s, Error: %v", userID, hostURL, err)
		return nil, err
	}
	
	log.Printf("GetScanByHost - Found scan ID: %d, UUID: %s, TargetURL: %s", scan.ID, scan.ScanUUID, scan.TargetURL)
	return scan, nil
}

// GetScanByUUID retrieves a scan by UUID with authorization check
func (s *Service) GetScanByUUID(scanUUID string, userID int) (*database.Scan, error) {
	scan := &database.Scan{}
	
	err := s.db.QueryRow(`
		SELECT id, scan_uuid, user_id, target_url, max_depth, max_pages, status, progress, started_at, completed_at, created_at
		FROM scans 
		WHERE scan_uuid = ? AND user_id = ?`,
		scanUUID, userID).Scan(
		&scan.ID, &scan.ScanUUID, &scan.UserID, &scan.TargetURL, &scan.MaxDepth, &scan.MaxPages,
		&scan.Status, &scan.Progress, &scan.StartedAt, &scan.CompletedAt, &scan.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	return scan, nil
}

// GetScanByUUIDForAdmin allows admins to view any scan (no user_id restriction)
func (s *Service) GetScanByUUIDForAdmin(scanUUID string) (*database.Scan, error) {
	scan := &database.Scan{}
	
	err := s.db.QueryRow(`
		SELECT id, scan_uuid, user_id, target_url, max_depth, max_pages, status, progress, started_at, completed_at, created_at
		FROM scans 
		WHERE scan_uuid = ?`,
		scanUUID).Scan(
		&scan.ID, &scan.ScanUUID, &scan.UserID, &scan.TargetURL, &scan.MaxDepth, &scan.MaxPages,
		&scan.Status, &scan.Progress, &scan.StartedAt, &scan.CompletedAt, &scan.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	return scan, nil
}

// VerifyScanOwnership checks if a user owns a scan
func (s *Service) VerifyScanOwnership(scanUUID string, userID int) error {
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM scans 
		WHERE scan_uuid = ? AND user_id = ?`,
		scanUUID, userID).Scan(&count)
	
	if err != nil {
		return err
	}
	
	if count == 0 {
		return errors.New("scan not found or access denied")
	}
	
	return nil
}

// DeleteScanByUUID deletes a scan by UUID with authorization check
func (s *Service) DeleteScanByUUID(scanUUID string, userID int) error {
	// Verify ownership first
	err := s.VerifyScanOwnership(scanUUID, userID)
	if err != nil {
		return err
	}

	// Delete scan results first
	_, err = s.db.Exec(`DELETE FROM scan_results WHERE scan_uuid = ?`, scanUUID)
	if err != nil {
		return err
	}

	// Delete scan statistics
	_, err = s.db.Exec(`DELETE FROM scan_statistics WHERE scan_uuid = ?`, scanUUID)
	if err != nil {
		return err
	}

	// Delete scan files
	_, err = s.db.Exec(`DELETE FROM scan_files WHERE scan_uuid = ?`, scanUUID)
	if err != nil {
		return err
	}

	// Delete the scan itself
	_, err = s.db.Exec(`DELETE FROM scans WHERE scan_uuid = ? AND user_id = ?`, scanUUID, userID)
	if err != nil {
		return err
	}

	return nil
}

// GetScanResultsByUUID retrieves scan results by UUID with authorization check
func (s *Service) GetScanResultsByUUID(scanUUID string, userID int) ([]database.ScanResult, error) {
	// Verify ownership first (admin can view any scan results)
	user, err := s.GetUserByID(userID)
	if err != nil {
		return nil, err
	}
	
	if user.Role != "admin" { // Only check ownership if not admin
		err := s.VerifyScanOwnership(scanUUID, userID)
		if err != nil {
			return nil, err
		}
	}

	rows, err := s.db.Query(`
		SELECT id, scan_id, scan_uuid, endpoint_type, url, method, parameters, form_data, headers, description, created_at
		FROM scan_results 
		WHERE scan_uuid = ?
		ORDER BY created_at DESC`,
		scanUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []database.ScanResult
	for rows.Next() {
		var result database.ScanResult
		var paramsJSON, formDataJSON, headersJSON sql.NullString

		err := rows.Scan(
			&result.ID, &result.ScanID, &result.ScanUUID, &result.EndpointType, &result.URL, &result.Method,
			&paramsJSON, &formDataJSON, &headersJSON, &result.Description, &result.CreatedAt)
		if err != nil {
			log.Printf("Error scanning result row: %v", err)
			continue
		}

		// Parse JSON fields
		if paramsJSON.Valid && paramsJSON.String != "" {
			json.Unmarshal([]byte(paramsJSON.String), &result.Parameters)
			// Decode HTML entities in parameter names and values
			result.Parameters = decodeHTMLEntitiesInMap(result.Parameters)
		} else {
			result.Parameters = make(map[string]interface{})
		}

		if formDataJSON.Valid && formDataJSON.String != "" {
			json.Unmarshal([]byte(formDataJSON.String), &result.FormData)
		} else {
			result.FormData = make(map[string]interface{})
		}

		if headersJSON.Valid && headersJSON.String != "" {
			json.Unmarshal([]byte(headersJSON.String), &result.Headers)
		} else {
			result.Headers = make(map[string]interface{})
		}

		results = append(results, result)
	}

	return results, nil
}


// createAllURLsFile creates a combined allurls.txt file with all discovered URLs for Axiom integration
func (s *Service) createAllURLsFile(results []database.ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Use a map to track unique URLs
	uniqueURLs := make(map[string]bool)
	
	// Collect all unique URLs from scan results
	for _, result := range results {
		if result.URL != "" && !uniqueURLs[result.URL] {
			uniqueURLs[result.URL] = true
			_, err = file.WriteString(result.URL + "\n")
			if err != nil {
				return err
			}
		}
	}
	
	log.Printf("Created allurls.txt with %d unique URLs", len(uniqueURLs))
	return nil
}

// createAllURLsFileFromScanData creates a combined allurls.txt file from ScanningData for Axiom integration
func (s *Service) createAllURLsFileFromScanData(scanData *scanningData.ScanningData, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Use a map to track unique URLs
	uniqueURLs := make(map[string]bool)
	
	// Collect all unique URLs from GET endpoints
	for _, endpoint := range scanData.GETEndpoints {
		if endpoint.URL != "" && !uniqueURLs[endpoint.URL] {
			uniqueURLs[endpoint.URL] = true
			_, err = file.WriteString(endpoint.URL + "\n")
			if err != nil {
				return err
			}
		}
	}
	
	// Collect all unique URLs from POST endpoints
	for _, endpoint := range scanData.POSTEndpoints {
		if endpoint.URL != "" && !uniqueURLs[endpoint.URL] {
			uniqueURLs[endpoint.URL] = true
			_, err = file.WriteString(endpoint.URL + "\n")
			if err != nil {
				return err
			}
		}
	}
	
	// Collect all unique URLs from JavaScript endpoints
	for _, endpoint := range scanData.JSEndpoints {
		if endpoint.URL != "" && !uniqueURLs[endpoint.URL] {
			uniqueURLs[endpoint.URL] = true
			_, err = file.WriteString(endpoint.URL + "\n")
			if err != nil {
				return err
			}
		}
	}
	
	log.Printf("Created allurls.txt with %d unique URLs from scan data", len(uniqueURLs))
	return nil
}

