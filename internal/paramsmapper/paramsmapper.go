package paramsmapper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

var totalRequests int
var logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
var ignoreCertErrors bool
var numBaselines = 3

type Request struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Data        string            `json:"data"`
	ContentType string            `json:"content_type"`
	Timeout     int               `json:"timeout"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type Results struct {
	Params        []string `json:"params"`
	FormParams    []string `json:"form_params"`
	TotalRequests int      `json:"total_requests"`
	Aborted       bool     `json:"aborted"`
	AbortReason   string   `json:"abort_reason"`
	Request       Request  `json:"request"`
}

type ProgressInfo struct {
	Current     int    `json:"current"`
	Total       int    `json:"total"`
	Percentage  int    `json:"percentage"`
	Stage       string `json:"stage"`
	Message     string `json:"message"`
	Discovered  int    `json:"discovered"`
}

type ProgressCallback func(ProgressInfo)

type ResponseData struct {
	Body        []byte
	StatusCode  int
	Reflections int
}

type InitialResponses struct {
	Responses     []ResponseData
	SameBody      bool
	AreConsistent bool
}

// DiscoverParams discovers valid parameters for a given request
func DiscoverParams(request Request, params []string, chunkSize int) Results {
	return DiscoverParamsWithProgress(request, params, chunkSize, nil)
}

// DiscoverParamsWithProgress discovers valid parameters with progress tracking
func DiscoverParamsWithProgress(request Request, params []string, chunkSize int, callback ProgressCallback) Results {
	totalParams := len(params)
	
	// Progress: 0-10% - Initial setup
	if callback != nil {
		callback(ProgressInfo{
			Current:    0,
			Total:      totalParams,
			Percentage: 0,
			Stage:      "initialization",
			Message:    "Initializing parameter discovery...",
			Discovered: 0,
		})
	}

	initialResponses := makeInitialRequests(request)

	// Progress: 10-15% - Baseline check
	if callback != nil {
		callback(ProgressInfo{
			Current:    totalParams / 10,
			Total:      totalParams,
			Percentage: 10,
			Stage:      "baseline",
			Message:    "Checking baseline responses...",
			Discovered: 0,
		})
	}

	// Check if baseline responses are consistent
	if !initialResponses.AreConsistent {
		logger.Warn("Baseline responses differ significantly. The page appears to be too dynamic. Scanning will be skipped.")
		if callback != nil {
			callback(ProgressInfo{
				Current:    totalParams,
				Total:      totalParams,
				Percentage: 100,
				Stage:      "aborted",
				Message:    "Scanning aborted - responses too dynamic",
				Discovered: 0,
			})
		}
		return Results{
			Params:        []string{},
			FormParams:    []string{},
			Aborted:       true,
			AbortReason:   "Baseline responses differ significantly",
			TotalRequests: totalRequests,
			Request:       request,
		}
	}

	// Progress: 15-20% - Form extraction
	if callback != nil {
		callback(ProgressInfo{
			Current:    totalParams / 5,
			Total:      totalParams,
			Percentage: 15,
			Stage:      "forms",
			Message:    "Extracting form parameters...",
			Discovered: 0,
		})
	}

	formsParams := extractFormParams(initialResponses.Responses[0].Body)
	logger.Info("Extracted form parameters", "count", len(formsParams), "parameters", formsParams)

	params = append(params, formsParams...)
	
	// Progress: 20-95% - Parameter discovery
	validParams := discoverValidParamsWithProgress(request, params, initialResponses, chunkSize, callback)
	
	// Progress: 95-100% - Finalization
	if callback != nil {
		callback(ProgressInfo{
			Current:    totalParams,
			Total:      totalParams,
			Percentage: 100,
			Stage:      "completed",
			Message:    "Parameter discovery completed",
			Discovered: len(validParams),
		})
	}

	return Results{
		Params:        validParams,
		FormParams:    formsParams,
		TotalRequests: totalRequests,
		Request:       request,
	}
}

func discoverValidParams(request Request, params []string, initialResponses InitialResponses, chunkSize int) []string {
	return discoverValidParamsWithProgress(request, params, initialResponses, chunkSize, nil)
}

func discoverValidParamsWithProgress(request Request, params []string, initialResponses InitialResponses, chunkSize int, callback ProgressCallback) []string {
	totalParams := len(params)
	parts := chunkParams(params, chunkSize)
	
	// Progress: 20-40% - Chunk filtering
	if callback != nil {
		callback(ProgressInfo{
			Current:    totalParams / 4,
			Total:      totalParams,
			Percentage: 20,
			Stage:      "chunking",
			Message:    "Testing parameter chunks...",
			Discovered: 0,
		})
	}
	
	validParts := filterParts(request, parts, initialResponses)

	// Progress: 40-60% - Valid parts found
	if callback != nil {
		callback(ProgressInfo{
			Current:    totalParams / 2,
			Total:      totalParams,
			Percentage: 40,
			Stage:      "filtering",
			Message:    fmt.Sprintf("Found %d valid parameter chunks", len(validParts)),
			Discovered: 0,
		})
	}

	paramSet := make(map[string]bool)
	var validParams []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	var processedCount int

	for i, part := range validParts {
		wg.Add(1)
		go func(part []string, partIndex int) {
			defer wg.Done()
			for _, param := range recursiveFilter(request, part, initialResponses) {
				mu.Lock()
				if !paramSet[param] {
					paramSet[param] = true
					validParams = append(validParams, param)
					logger.Info("Valid parameter discovered", "parameter", param)
				}
				processedCount++
				
				// Update progress every 10 parameters or at the end
				if processedCount%10 == 0 || processedCount == totalParams {
					progress := 40 + int(float64(processedCount)/float64(totalParams)*50) // 40-90%
					if callback != nil {
						callback(ProgressInfo{
							Current:    processedCount,
							Total:      totalParams,
							Percentage: progress,
							Stage:      "discovery",
							Message:    fmt.Sprintf("Testing parameters... (%d/%d)", processedCount, totalParams),
							Discovered: len(validParams),
						})
					}
				}
				mu.Unlock()
			}
		}(part, i)
	}

	wg.Wait()
	return validParams
}

func filterParts(request Request, parts [][]string, initialResponses InitialResponses) [][]string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var validParts [][]string

	for _, part := range parts {
		wg.Add(1)
		go func(part []string) {
			defer wg.Done()
			params := generateParams(part)
			response := makeRequest(request, params)

			if responseChanged(initialResponses.Responses, response, initialResponses.SameBody) {
				mu.Lock()
				validParts = append(validParts, part)
				mu.Unlock()
			}
		}(part)
	}
	wg.Wait()
	return validParts
}

func recursiveFilter(request Request, params []string, initialResponses InitialResponses) []string {
	if len(params) == 1 {
		return params
	}
	mid := len(params) / 2
	left := params[:mid]
	right := params[mid:]

	leftParams := generateParams(left)
	rightParams := generateParams(right)

	leftResponse := makeRequest(request, leftParams)
	rightResponse := makeRequest(request, rightParams)

	var validParams []string
	if responseChanged(initialResponses.Responses, leftResponse, initialResponses.SameBody) {
		validParams = append(validParams, recursiveFilter(request, left, initialResponses)...)
	}
	if responseChanged(initialResponses.Responses, rightResponse, initialResponses.SameBody) {
		validParams = append(validParams, recursiveFilter(request, right, initialResponses)...)
	}
	return validParams
}

func makeInitialRequests(request Request) InitialResponses {
	var baselineResponses []ResponseData
	for i := 0; i < numBaselines; i++ {
		resp := makeRequest(request, url.Values{})
		baselineResponses = append(baselineResponses, resp)
	}

	return InitialResponses{
		Responses:     baselineResponses,
		SameBody:      baselineResponsesAreConsistent(baselineResponses, responsesAreEqual),
		AreConsistent: baselineResponsesAreConsistent(baselineResponses, responsesAreSimilar),
	}
}

func makeRequest(request Request, params url.Values) ResponseData {
	var req *http.Request
	var err error
	totalRequests++
	parsedURL, err := url.Parse(request.URL)
	if err != nil {
		logger.Error("Failed to parse request URL", "error", err)
		return ResponseData{}
	}

    existingParams := parsedURL.Query()
    for key, values := range params {
        for _, value := range values {
            // Match paramsmap behavior: append values (do not overwrite)
            existingParams.Add(key, value)
        }
    }
	parsedURL.RawQuery = existingParams.Encode()
	requestURL := parsedURL.String()
	if request.Method == "GET" {
		req, err = http.NewRequest(request.Method, requestURL, nil)
	} else {
		var body []byte
		if request.ContentType == "json" {
			body = []byte(request.Data)
			req, err = http.NewRequest(request.Method, requestURL, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
		} else if request.ContentType == "xml" {
			body = []byte(request.Data)
			req, err = http.NewRequest(request.Method, requestURL, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/xml")
		} else {
			req, err = http.NewRequest(request.Method, requestURL, strings.NewReader(params.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	req.Header.Set("User-Agent", randomUserAgent())
	
	// Add custom headers
	for headerName, headerValue := range request.Headers {
		req.Header.Set(headerName, headerValue)
	}
	
	if err != nil {
		logger.Error("Failed to create request", "error", err)
	}

	client := createHTTPClient(request.Timeout)
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Failed to make request", "error", err)
		return ResponseData{}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read response body", "error", err)
	}

	reflections := countReflections(params, body)
	return ResponseData{Body: body, StatusCode: resp.StatusCode, Reflections: reflections}
}

// SaveReport saves the results to a JSON file
func SaveReport(reportPath string, results Results) {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		logger.Error("Error marshalling results to JSON", slog.String("error", err.Error()))
		return
	}

	file, err := os.Create(reportPath)
	if err != nil {
		logger.Error("Error creating/opening report file", slog.String("error", err.Error()), slog.String("path", reportPath))
		return
	}
	defer file.Close()

	_, err = file.Write(jsonData)
	if err != nil {
		logger.Error("Error writing JSON to file", slog.String("error", err.Error()), slog.String("path", reportPath))
		return
	}

	logger.Info("Report saved successfully", slog.String("path", reportPath))
}
