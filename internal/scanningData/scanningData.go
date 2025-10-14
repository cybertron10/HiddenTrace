package scanningData

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"vidusec/internal/enhancedCrawler"
)

// EndpointData represents a complete endpoint for XSS scanning
type EndpointData struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Type        string            `json:"type"` // "get", "post", "js_api"
	Source      string            `json:"source"` // "form", "link", "javascript"
	Parameters  map[string]string `json:"parameters"`
	FormData    map[string]string `json:"form_data,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Description string            `json:"description,omitempty"`
}

// ScanningData contains all endpoints ready for XSS testing
type ScanningData struct {
	GETEndpoints  []EndpointData `json:"get_endpoints"`
	POSTEndpoints []EndpointData `json:"post_endpoints"`
	JSEndpoints   []EndpointData `json:"js_endpoints"`
	Summary       DataSummary    `json:"summary"`
}

// DataSummary provides overview of discovered data
type DataSummary struct {
	TotalEndpoints int `json:"total_endpoints"`
	GETCount       int `json:"get_count"`
	POSTCount      int `json:"post_count"`
	JSCount        int `json:"js_count"`
	TotalParams    int `json:"total_parameters"`
}

// CreateScanningData creates structured data for XSS scanning
func CreateScanningData(urls []string, formFields []enhancedCrawler.FormField, jsAPIs []enhancedCrawler.JavaScriptAPI, hiddenFields []enhancedCrawler.HiddenField, postEndpoints []enhancedCrawler.POSTEndpoint) *ScanningData {
	scanningData := &ScanningData{
		GETEndpoints:  []EndpointData{},
		POSTEndpoints: []EndpointData{},
		JSEndpoints:   []EndpointData{},
	}

	// Process URLs for GET endpoints
	for _, url := range urls {
		if isGETEndpoint(url) {
			endpoint := createGETEndpoint(url)
			scanningData.GETEndpoints = append(scanningData.GETEndpoints, endpoint)
		}
	}

	// Process form fields for POST endpoints
	for _, field := range formFields {
		if field.Method == "POST" {
			endpoint := createPOSTEndpointFromForm(field, hiddenFields)
			scanningData.POSTEndpoints = append(scanningData.POSTEndpoints, endpoint)
		}
	}

	// Process JavaScript APIs
	for _, api := range jsAPIs {
		endpoint := createJSEndpoint(api)
		scanningData.JSEndpoints = append(scanningData.JSEndpoints, endpoint)
	}

	// Process POST endpoints
	for _, postEndpoint := range postEndpoints {
		endpoint := createPOSTEndpoint(postEndpoint, hiddenFields)
		scanningData.POSTEndpoints = append(scanningData.POSTEndpoints, endpoint)
	}

	// Remove duplicates and calculate summary
	scanningData.removeDuplicates()
	scanningData.calculateSummary()

	return scanningData
}

// createGETEndpoint creates GET endpoint data
func createGETEndpoint(url string) EndpointData {
	// Parse URL to extract parameters
	params := extractURLParameters(url)
	
	return EndpointData{
		URL:        url,
		Method:     "GET",
		Type:       "get",
		Source:     "link",
		Parameters: params,
		Headers: map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		},
		Description: "GET endpoint discovered from links",
	}
}

// createPOSTEndpointFromForm creates POST endpoint from form data
func createPOSTEndpointFromForm(field enhancedCrawler.FormField, hiddenFields []enhancedCrawler.HiddenField) EndpointData {
	params := make(map[string]string)
	formData := make(map[string]string)
	
	// Add form field
	params[field.Name] = field.Value
	formData[field.Name] = field.Value
	
	// Add related hidden fields
	for _, hidden := range hiddenFields {
		if hidden.URL == field.URL {
			params[hidden.Name] = hidden.Value
			formData[hidden.Name] = hidden.Value
		}
	}
	
	return EndpointData{
		URL:        field.URL,
		Method:     "POST",
		Type:       "post",
		Source:     "form",
		Parameters: params,
		FormData:   formData,
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		},
		Description: fmt.Sprintf("POST endpoint from form: %s", field.Action),
	}
}

// createJSEndpoint creates JavaScript API endpoint
func createJSEndpoint(api enhancedCrawler.JavaScriptAPI) EndpointData {
	params := extractURLParameters(api.Endpoint)
	
	return EndpointData{
		URL:        api.Endpoint,
		Method:     api.Method,
		Type:       "js_api",
		Source:     "javascript",
		Parameters: params,
		Headers: map[string]string{
			"Content-Type": "application/json",
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		},
		Description: "JavaScript API endpoint",
	}
}

// createPOSTEndpoint creates POST endpoint from discovered POST endpoints
func createPOSTEndpoint(postEndpoint enhancedCrawler.POSTEndpoint, hiddenFields []enhancedCrawler.HiddenField) EndpointData {
	params := extractURLParameters(postEndpoint.Endpoint)
	formData := make(map[string]string)
	
	// Add related hidden fields
	for _, hidden := range hiddenFields {
		if hidden.URL == postEndpoint.URL {
			params[hidden.Name] = hidden.Value
			formData[hidden.Name] = hidden.Value
		}
	}
	
	return EndpointData{
		URL:        postEndpoint.Endpoint,
		Method:     "POST",
		Type:       "post",
		Source:     "discovered",
		Parameters: params,
		FormData:   formData,
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		},
		Description: "POST endpoint discovered",
	}
}

// extractURLParameters extracts parameters from URL
func extractURLParameters(url string) map[string]string {
	params := make(map[string]string)
	
	// Simple parameter extraction
	if strings.Contains(url, "?") {
		parts := strings.Split(url, "?")
		if len(parts) > 1 {
			queryString := parts[1]
			pairs := strings.Split(queryString, "&")
			for _, pair := range pairs {
				if strings.Contains(pair, "=") {
					kv := strings.SplitN(pair, "=", 2)
					if len(kv) == 2 {
						params[kv[0]] = kv[1]
					}
				}
			}
		}
	}
	
	return params
}

// isGETEndpoint determines if URL is a GET endpoint
func isGETEndpoint(url string) bool {
	// Exclude obvious POST endpoints
	postIndicators := []string{"login.php", "contact.php", "submit", "post"}
	for _, indicator := range postIndicators {
		if strings.Contains(strings.ToLower(url), indicator) {
			return false
		}
	}
	return true
}

// removeDuplicates removes duplicate endpoints
func (sd *ScanningData) removeDuplicates() {
	// Remove duplicate GET endpoints
	seen := make(map[string]bool)
	var uniqueGET []EndpointData
	for _, endpoint := range sd.GETEndpoints {
		if !seen[endpoint.URL] {
			seen[endpoint.URL] = true
			uniqueGET = append(uniqueGET, endpoint)
		}
	}
	sd.GETEndpoints = uniqueGET
	
	// Remove duplicate POST endpoints
	seen = make(map[string]bool)
	var uniquePOST []EndpointData
	for _, endpoint := range sd.POSTEndpoints {
		if !seen[endpoint.URL] {
			seen[endpoint.URL] = true
			uniquePOST = append(uniquePOST, endpoint)
		}
	}
	sd.POSTEndpoints = uniquePOST
	
	// Remove duplicate JS endpoints
	seen = make(map[string]bool)
	var uniqueJS []EndpointData
	for _, endpoint := range sd.JSEndpoints {
		if !seen[endpoint.URL] {
			seen[endpoint.URL] = true
			uniqueJS = append(uniqueJS, endpoint)
		}
	}
	sd.JSEndpoints = uniqueJS
}

// calculateSummary calculates summary statistics
func (sd *ScanningData) calculateSummary() {
	sd.Summary.GETCount = len(sd.GETEndpoints)
	sd.Summary.POSTCount = len(sd.POSTEndpoints)
	sd.Summary.JSCount = len(sd.JSEndpoints)
	sd.Summary.TotalEndpoints = sd.Summary.GETCount + sd.Summary.POSTCount + sd.Summary.JSCount
	
	// Count total parameters
	totalParams := 0
	for _, endpoint := range sd.GETEndpoints {
		totalParams += len(endpoint.Parameters)
	}
	for _, endpoint := range sd.POSTEndpoints {
		totalParams += len(endpoint.Parameters)
		totalParams += len(endpoint.FormData)
	}
	for _, endpoint := range sd.JSEndpoints {
		totalParams += len(endpoint.Parameters)
	}
	sd.Summary.TotalParams = totalParams
}

// SaveToFile saves scanning data to JSON file
func (sd *ScanningData) SaveToFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sd)
}

// SaveEndpointsForXSS saves endpoints in format ready for XSS scanning
func (sd *ScanningData) SaveEndpointsForXSS(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Write header
	_, err = file.WriteString("# XSS Scanning Endpoints\n")
	if err != nil {
		return err
	}
	
	_, err = file.WriteString("# Format: METHOD | URL | PARAMETERS | FORM_DATA | HEADERS\n\n")
	if err != nil {
		return err
	}
	
	// Write GET endpoints
	_, err = file.WriteString("## GET Endpoints\n")
	if err != nil {
		return err
	}
	
	for _, endpoint := range sd.GETEndpoints {
		line := fmt.Sprintf("GET | %s | %v | - | %v\n", 
			endpoint.URL, endpoint.Parameters, endpoint.Headers)
		_, err = file.WriteString(line)
		if err != nil {
			return err
		}
	}
	
	// Write POST endpoints
	_, err = file.WriteString("\n## POST Endpoints\n")
	if err != nil {
		return err
	}
	
	for _, endpoint := range sd.POSTEndpoints {
		line := fmt.Sprintf("POST | %s | %v | %v | %v\n", 
			endpoint.URL, endpoint.Parameters, endpoint.FormData, endpoint.Headers)
		_, err = file.WriteString(line)
		if err != nil {
			return err
		}
	}
	
	// Write JS endpoints
	_, err = file.WriteString("\n## JavaScript API Endpoints\n")
	if err != nil {
		return err
	}
	
	for _, endpoint := range sd.JSEndpoints {
		line := fmt.Sprintf("JS | %s | %v | - | %v\n", 
			endpoint.URL, endpoint.Parameters, endpoint.Headers)
		_, err = file.WriteString(line)
		if err != nil {
			return err
		}
	}
	
	return nil
}

