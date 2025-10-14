package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"vidusec/internal/enhancedCrawler"
	"vidusec/internal/enhancedParamExtractor"
	"vidusec/internal/scanningData"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	
	switch command {
	case "crawl":
		runCrawl()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func runCrawl() {
	// Create a new flag set for crawl command
	fs := flag.NewFlagSet("crawl", flag.ExitOnError)
	
	var maxDepth = fs.Int("depth", 10, "Maximum crawl depth")
	var maxPages = fs.Int("pages", 20000, "Maximum number of pages to crawl")
	var output = fs.String("output", "", "Output file to save discovered URLs")
	var headers = fs.String("headers", "", "Custom headers for authenticated crawling (format: 'Header1: Value1, Header2: Value2')")
	var headersFile = fs.String("headers-file", "", "File containing custom headers (one per line, format: 'Header: Value')")
	
	// Parse flags, skipping the first two args (program name and "crawl")
	err := fs.Parse(os.Args[2:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}
	
	// Get the URL argument
	args := fs.Args()
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Error: URL is required")
		fmt.Fprintln(os.Stderr, "Usage: vidusec crawl [flags] <URL>")
		fs.PrintDefaults()
		os.Exit(1)
	}
	
	url := args[0]
	
	// Replace localhost with Windows host IP for WSL compatibility
	if strings.Contains(url, "127.0.0.1") {
		url = strings.Replace(url, "127.0.0.1", "172.21.64.1", 1)
	}
	
	// Parse custom headers
	var customHeaders map[string]string
	if *headersFile != "" {
		customHeaders, err = parseHeadersFromFile(*headersFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading headers file: %v\n", err)
			os.Exit(1)
		}
	} else {
		customHeaders = parseHeaders(*headers)
	}
	
	fmt.Fprintf(os.Stderr, "Enhanced crawling %s (max depth: %d, max pages: %d)...\n", url, *maxDepth, *maxPages)
	if len(customHeaders) > 0 {
		fmt.Fprintf(os.Stderr, "Using custom headers: %d headers provided\n", len(customHeaders))
	}
	
	result, err := enhancedCrawler.EnhancedCrawl(url, *maxDepth, *maxPages, customHeaders)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error crawling: %v\n", err)
		os.Exit(1)
	}
	
	// Output results
	var outputFile *os.File
	if *output != "" {
		outputFile, err = os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer outputFile.Close()
	}
	
	for _, u := range result.URLs {
		fmt.Println(u)
		if outputFile != nil {
			fmt.Fprintln(outputFile, u)
		}
	}
	
	fmt.Fprintf(os.Stderr, "Crawled %d URLs\n", len(result.URLs))
	fmt.Fprintf(os.Stderr, "Found %d form fields\n", len(result.FormFields))
	fmt.Fprintf(os.Stderr, "Found %d hidden fields\n", len(result.HiddenFields))
	fmt.Fprintf(os.Stderr, "Found %d JavaScript APIs\n", len(result.JavaScriptAPIs))
	fmt.Fprintf(os.Stderr, "Found %d POST endpoints\n", len(result.POSTEndpoints))
	
	// Create structured scanning data
	fmt.Fprintf(os.Stderr, "Creating structured data for XSS scanning...\n")
	scanData := scanningData.CreateScanningData(
		result.URLs,
		result.FormFields,
		result.JavaScriptAPIs,
		result.HiddenFields,
		result.POSTEndpoints,
	)
	
	// Print summary
	fmt.Fprintf(os.Stderr, "Scanning Data Summary:\n")
	fmt.Fprintf(os.Stderr, "  GET Endpoints: %d\n", scanData.Summary.GETCount)
	fmt.Fprintf(os.Stderr, "  POST Endpoints: %d\n", scanData.Summary.POSTCount)
	fmt.Fprintf(os.Stderr, "  JS API Endpoints: %d\n", scanData.Summary.JSCount)
	fmt.Fprintf(os.Stderr, "  Total Parameters: %d\n", scanData.Summary.TotalParams)
	
	// Save structured data for XSS scanning
	err = scanData.SaveToFile("scanning_data.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving scanning data: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "Saved structured scanning data to scanning_data.json\n")
	}
	
	// Save endpoints in XSS-ready format
	err = scanData.SaveEndpointsForXSS("xss_endpoints.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving XSS endpoints: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "Saved XSS-ready endpoints to xss_endpoints.txt\n")
	}
	
	// Extract parameters from all sources (for backward compatibility)
	fmt.Fprintf(os.Stderr, "Extracting parameters from all sources...\n")
	parameters := enhancedParamExtractor.ExtractAllParameters(result)
	
	if len(parameters) > 0 {
		// Save parameters to customwordlist.txt
		err = enhancedParamExtractor.SaveParametersToFile(parameters, "customwordlist.txt")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving parameters to customwordlist.txt: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Extracted %d unique parameters and saved to customwordlist.txt\n", len(parameters))
		}
	} else {
		fmt.Fprintf(os.Stderr, "No parameters found in discovered data\n")
	}
}

// parseHeaders parses the headers string into a map
func parseHeaders(headersStr string) map[string]string {
	headers := make(map[string]string)
	
	if headersStr == "" {
		return headers
	}
	
	// Handle both comma-separated and newline-separated headers
	// First, replace newlines with commas for consistent parsing
	headersStr = strings.ReplaceAll(headersStr, "\n", ",")
	headersStr = strings.ReplaceAll(headersStr, "\r", "")
	
	// Split by comma to get individual headers
	headerPairs := strings.Split(headersStr, ",")
	
	for _, pair := range headerPairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		
		// Split by colon to get header name and value
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// Remove quotes if present
			value = strings.Trim(value, "\"'")
			if name != "" && value != "" {
				headers[name] = value
			}
		}
	}
	
	return headers
}

// parseHeadersFromFile reads headers from a file
func parseHeadersFromFile(filename string) (map[string]string, error) {
	headers := make(map[string]string)
	
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		
		// Split by colon to get header name and value
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// Remove quotes if present
			value = strings.Trim(value, "\"'")
			if name != "" && value != "" {
				headers[name] = value
			}
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	
	return headers, nil
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "ViduSec - Integrated Security Tools")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  vidusec crawl [flags] <URL>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  crawl    Crawl a website to discover URLs")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags:")
	fmt.Fprintln(os.Stderr, "  -depth int")
	fmt.Fprintln(os.Stderr, "        Maximum crawl depth (default 10)")
	fmt.Fprintln(os.Stderr, "  -headers string")
	fmt.Fprintln(os.Stderr, "        Custom headers for authenticated crawling")
	fmt.Fprintln(os.Stderr, "        Format: 'Header1: Value1, Header2: Value2'")
	fmt.Fprintln(os.Stderr, "  -headers-file string")
	fmt.Fprintln(os.Stderr, "        File containing custom headers (one per line)")
	fmt.Fprintln(os.Stderr, "        Format: 'Header: Value' (supports comments with #)")
	fmt.Fprintln(os.Stderr, "  -output string")
	fmt.Fprintln(os.Stderr, "        Output file to save discovered URLs")
	fmt.Fprintln(os.Stderr, "  -pages int")
	fmt.Fprintln(os.Stderr, "        Maximum number of pages to crawl (default 20000)")
}
