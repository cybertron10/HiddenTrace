package enhancedParamExtractor

import (
	"fmt"
	"html"
	"net/url"
	"os"
	"sort"
	"strings"

	"HiddenTrace/internal/enhancedCrawler"
)

// ExtractAllParameters extracts parameters from all sources
func ExtractAllParameters(result *enhancedCrawler.CrawlResult) []string {
	paramSet := make(map[string]bool)
	
	// Extract from URLs (existing functionality)
	for _, u := range result.URLs {
		parsedURL, err := url.Parse(u)
		if err != nil {
			continue
		}
		
		// Extract parameters from query string
		queryParams := parsedURL.Query()
		for param := range queryParams {
			cleanParam := cleanParameterName(param)
			if cleanParam != "" {
				paramSet[cleanParam] = true
			}
		}
		
		// Extract from fragment
		if parsedURL.Fragment != "" {
			fragmentParams := extractFromFragment(parsedURL.Fragment)
			for _, param := range fragmentParams {
				cleanParam := cleanParameterName(param)
				if cleanParam != "" {
					paramSet[cleanParam] = true
				}
			}
		}
	}
	
	// Extract from form fields
	for _, field := range result.FormFields {
		cleanParam := cleanParameterName(field.Name)
		if cleanParam != "" {
			paramSet[cleanParam] = true
		}
	}
	
	// Extract from hidden fields
	for _, field := range result.HiddenFields {
		cleanParam := cleanParameterName(field.Name)
		if cleanParam != "" {
			paramSet[cleanParam] = true
		}
	}
	
	// Extract from JavaScript APIs (parse endpoint parameters)
	for _, api := range result.JavaScriptAPIs {
		parsedURL, err := url.Parse(api.Endpoint)
		if err != nil {
			continue
		}
		
		queryParams := parsedURL.Query()
		for param := range queryParams {
			cleanParam := cleanParameterName(param)
			if cleanParam != "" {
				paramSet[cleanParam] = true
			}
		}
	}
	
	// Extract from POST endpoints
	for _, endpoint := range result.POSTEndpoints {
		parsedURL, err := url.Parse(endpoint.Endpoint)
		if err != nil {
			continue
		}
		
		queryParams := parsedURL.Query()
		for param := range queryParams {
			cleanParam := cleanParameterName(param)
			if cleanParam != "" {
				paramSet[cleanParam] = true
			}
		}
	}
	
	// Convert map to sorted slice
	var parameters []string
	for param := range paramSet {
		parameters = append(parameters, param)
	}
	sort.Strings(parameters)
	
	return parameters
}

// ExtractFormData extracts all form-related data
func ExtractFormData(result *enhancedCrawler.CrawlResult) []FormData {
	var formData []FormData
	
	// Process form fields
	for _, field := range result.FormFields {
		formData = append(formData, FormData{
			Type:     "form_field",
			URL:      field.URL,
			Method:   field.Method,
			Endpoint: field.Action,
			Name:     field.Name,
			Value:    field.Value,
			FieldType: field.Type,
			Required: field.Required,
		})
	}
	
	// Process hidden fields
	for _, field := range result.HiddenFields {
		formData = append(formData, FormData{
			Type:     "hidden_field",
			URL:      field.URL,
			Name:     field.Name,
			Value:    field.Value,
		})
	}
	
	// Process JavaScript APIs
	for _, api := range result.JavaScriptAPIs {
		formData = append(formData, FormData{
			Type:     "js_api",
			URL:      api.URL,
			Method:   api.Method,
			Endpoint: api.Endpoint,
		})
	}
	
	// Process POST endpoints
	for _, endpoint := range result.POSTEndpoints {
		formData = append(formData, FormData{
			Type:     "post_endpoint",
			URL:      endpoint.URL,
			Method:   "POST",
			Endpoint: endpoint.Endpoint,
		})
	}
	
	return formData
}

// FormData represents extracted form-related data
type FormData struct {
	Type      string
	URL       string
	Method    string
	Endpoint  string
	Name      string
	Value     string
	FieldType string
	Required  bool
}

// cleanParameterName cleans and normalizes parameter names
func cleanParameterName(param string) string {
	originalParam := param
	param = strings.TrimSpace(param)
	
	// Decode HTML entities first
	param = html.UnescapeString(param)
	
	// Debug logging
	if originalParam != param {
		fmt.Printf("DEBUG: Parameter cleaned: '%s' -> '%s'\n", originalParam, param)
	}
	
	// Special debug for the problematic parameter
	if originalParam == "amp;other" || param == "amp;other" {
		fmt.Printf("DEBUG: Found 'amp;other' parameter - original: '%s', cleaned: '%s'\n", originalParam, param)
	}
	
	// Skip empty or very short parameters
	if len(param) < 1 {
		return ""
	}
	
	// Skip common non-meaningful parameters (but keep 'q' as it's often used for search)
	skipParams := map[string]bool{
		"id": true, "page": true, "limit": true, "offset": true,
		"sort": true, "order": true, "format": true, "type": true,
		"lang": true, "locale": true, "timezone": true, "version": true,
		"token": true, "key": true, "secret": true, "hash": true,
		"timestamp": true, "date": true, "time": true, "debug": true,
		"test": true, "demo": true, "preview": true, "beta": true,
	}
	
	if skipParams[param] {
		return ""
	}
	
	// Remove common prefixes/suffixes
	param = strings.TrimPrefix(param, "param_")
	param = strings.TrimPrefix(param, "arg_")
	param = strings.TrimSuffix(param, "_param")
	param = strings.TrimSuffix(param, "_arg")
	
	return param
}

// extractFromFragment extracts parameters from URL fragment
func extractFromFragment(fragment string) []string {
	var params []string
	
	// Simple parameter extraction from fragments
	parts := strings.Split(fragment, "&")
	for _, part := range parts {
		if strings.Contains(part, "=") {
			keyValue := strings.SplitN(part, "=", 2)
			if len(keyValue) > 0 {
				param := strings.TrimSpace(keyValue[0])
				param = strings.TrimPrefix(param, "?")
				param = strings.TrimPrefix(param, "&")
				if param != "" {
					params = append(params, param)
				}
			}
		}
	}
	
	return params
}

// SaveParametersToFile saves parameters to a file
func SaveParametersToFile(parameters []string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	for _, param := range parameters {
		_, err := file.WriteString(param + "\n")
		if err != nil {
			return err
		}
	}
	
	return nil
}

// SaveFormDataToFile saves form data to a file
func SaveFormDataToFile(formData []FormData, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Write header
	_, err = file.WriteString("# Form Data Extraction Results\n")
	if err != nil {
		return err
	}
	
	_, err = file.WriteString("# Format: TYPE | URL | METHOD | ENDPOINT | NAME | VALUE | FIELD_TYPE | REQUIRED\n")
	if err != nil {
		return err
	}
	
	for _, data := range formData {
		line := fmt.Sprintf("%s | %s | %s | %s | %s | %s | %s | %t\n",
			data.Type, data.URL, data.Method, data.Endpoint, data.Name, data.Value, data.FieldType, data.Required)
		_, err = file.WriteString(line)
		if err != nil {
			return err
		}
	}
	
	return nil
}
