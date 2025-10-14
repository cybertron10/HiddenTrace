package enhancedCrawler

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CrawlResult contains all discovered data from crawling
type CrawlResult struct {
	URLs           []string
	FormFields     []FormField
	JavaScriptAPIs []JavaScriptAPI
	HiddenFields   []HiddenField
	POSTEndpoints  []POSTEndpoint
}

// FormField represents a form input field
type FormField struct {
	URL      string
	Method   string
	Action   string
	Name     string
	Type     string
	Value    string
	Required bool
}

// JavaScriptAPI represents an API endpoint found in JavaScript
type JavaScriptAPI struct {
	URL        string
	Method     string
	Endpoint   string
	Parameters []string
}

// HiddenField represents a hidden form field
type HiddenField struct {
	URL   string
	Name  string
	Value string
}

// POSTEndpoint represents a POST endpoint with its parameters
type POSTEndpoint struct {
	URL        string
	Endpoint   string
	Parameters []string
}

// EnhancedCrawl discovers URLs and extracts comprehensive data
func EnhancedCrawl(startURL string, maxDepth int, maxPages int, customHeaders map[string]string) (*CrawlResult, error) {
	// CRITICAL DEBUG: Test what content we get from the initial URL
	fmt.Fprintf(os.Stderr, "DEBUG: Testing initial URL content retrieval for: %s\n", startURL)
	testClient := &http.Client{Timeout: 10 * time.Second}
	testReq, _ := http.NewRequest(http.MethodGet, startURL, nil)
	for name, value := range customHeaders {
		testReq.Header.Set(name, value)
	}
	testResp, err := testClient.Do(testReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DEBUG: Test request failed: %v\n", err)
	} else {
		defer testResp.Body.Close()
		testBody := new(strings.Builder)
		io.Copy(testBody, testResp.Body)
		content := testBody.String()
		fmt.Fprintf(os.Stderr, "DEBUG: Test content length: %d bytes\n", len(content))
		if len(content) > 200 {
			fmt.Fprintf(os.Stderr, "DEBUG: Test content preview: %s...\n", content[:200])
		} else {
			fmt.Fprintf(os.Stderr, "DEBUG: Test content: %s\n", content)
		}
	}
	
	if maxDepth <= 0 { maxDepth = 1 }
	if maxPages <= 0 { maxPages = 1000 }

	start, err := url.Parse(startURL)
	if err != nil { return nil, fmt.Errorf("invalid start url: %w", err) }
	baseHost := start.Host
	
	// Blacklist of endpoints to avoid crawling
	blacklist := []string{
		"/login",
		"/logout", 
		"/signin",
		"/signout",
		"/auth",
		"/authenticate",
	}
	
	// Function to check if URL should be blacklisted
	isBlacklisted := func(url string) bool {
		urlLower := strings.ToLower(url)
		for _, blacklisted := range blacklist {
			if strings.Contains(urlLower, blacklisted) {
				return true
			}
		}
		return false
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   5 * time.Second,
			MaxIdleConns:          400,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       15 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			DisableCompression:    false, // Enable automatic decompression
		},
	}

	type item struct{ u string; d int }
	jobs := make(chan item, 20000)
	visited := make(map[string]bool)
	results := make(map[string]bool)
	
	// Mutex to protect customHeaders from race conditions
	headersMutex := &sync.Mutex{}
	var mu sync.Mutex
	pending := &sync.WaitGroup{}
	wg := &sync.WaitGroup{}

	// Enhanced patterns for comprehensive extraction
	urlPatterns := []string{
		// Standard HTML attributes
		`(?i)href\s*=\s*["']([^"']+)["']`,
		`(?i)href\s*=\s*([^\s"'>]+)`,
		`(?i)src\s*=\s*["']([^"']+)["']`,
		`(?i)src\s*=\s*([^\s"'>]+)`,
		`(?i)action\s*=\s*["']([^"']+)["']`,
		`(?i)action\s*=\s*([^\s"'>]+)`,
		
		// JavaScript API calls
		`(?i)(?:fetch|XMLHttpRequest|ajax)\s*\(\s*["']([^"']+)["']`,
		`(?i)\.post\s*\(\s*["']([^"']+)["']`,
		`(?i)\.get\s*\(\s*["']([^"']+)["']`,
		`(?i)\.put\s*\(\s*["']([^"']+)["']`,
		`(?i)\.delete\s*\(\s*["']([^"']+)["']`,
		`(?i)axios\.(?:get|post|put|delete)\s*\(\s*["']([^"']+)["']`,
		`(?i)\$\.(?:get|post|ajax)\s*\(\s*["']([^"']+)["']`,
		
		// Form elements
		`(?i)<a[^>]+href\s*=\s*["']([^"']+)["'][^>]*>`,
		`(?i)<link[^>]+href\s*=\s*["']([^"']+)["'][^>]*>`,
		`(?i)<script[^>]+src\s*=\s*["']([^"']+)["'][^>]*>`,
		`(?i)<img[^>]+src\s*=\s*["']([^"']+)["'][^>]*>`,
		`(?i)<iframe[^>]+src\s*=\s*["']([^"']+)["'][^>]*>`,
		`(?i)<form[^>]+action\s*=\s*["']([^"']+)["'][^>]*>`,
		`(?i)<object[^>]+data\s*=\s*["']([^"']+)["'][^>]*>`,
		`(?i)<embed[^>]+src\s*=\s*["']([^"']+)["'][^>]*>`,
		`(?i)<source[^>]+src\s*=\s*["']([^"']+)["'][^>]*>`,
		`(?i)<param[^>]+value\s*=\s*["']([^"']+)["'][^>]*>`,
		
		// Raw URLs
		`(?i)https?://[^\s"'<>]+`,
	}
	regexes := make([]*regexp.Regexp, 0, len(urlPatterns))
	for _, p := range urlPatterns { regexes = append(regexes, regexp.MustCompile(p)) }

	// Data extraction patterns
	formPattern := regexp.MustCompile(`(?i)<form[^>]*>(.*?)</form>`)
	inputPattern := regexp.MustCompile(`(?i)<input[^>]*name\s*=\s*["']([^"']+)["'][^>]*type\s*=\s*["']([^"']*)["'][^>]*value\s*=\s*["']([^"']*)["'][^>]*>`)
	hiddenPattern := regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']hidden["'][^>]*name\s*=\s*["']([^"']+)["'][^>]*value\s*=\s*["']([^"']*)["'][^>]*>`)
	
	// JavaScript API patterns - more flexible
	jsAPIPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)fetch\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)XMLHttpRequest.*open\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)\.(?:get|post|put|delete)\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)axios\.(?:get|post|put|delete)\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)\$\.(?:get|post|ajax)\s*\(\s*["']([^"']+)["']`),
	}

	skipExt := func(p string) bool {
		p = strings.ToLower(p)
		for _, ext := range []string{ ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot" } {
			if strings.HasSuffix(p, ext) { return true }
		}
		return false
	}

	normalize := func(u *url.URL) string {
		u.Fragment = ""
		return u.String()
	}

	resolve := func(raw string, page *url.URL) string {
		raw = strings.TrimSpace(raw)
		if raw == "" { return "" }
		if strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "#") {
			return ""
		}
		
		// Decode HTML entities before parsing URL
		decodedRaw := html.UnescapeString(raw)
		
		rel, err := url.Parse(decodedRaw)
		if err != nil { return "" }
		abs := page.ResolveReference(rel)
		if abs.Host != baseHost { return "" }
		if abs.Scheme != "http" && abs.Scheme != "https" { return "" }
		if skipExt(abs.Path) { return "" }
		return normalize(abs)
	}

	// Data storage
	var formFields []FormField
	var jsAPIs []JavaScriptAPI
	var hiddenFields []HiddenField
	var postEndpoints []POSTEndpoint
	var dataMu sync.Mutex

	worker := func() {
		defer wg.Done()
		for it := range jobs {
			func(it item) {
				defer pending.Done()
				if it.d > maxDepth { return }
				pageURL := it.u

				// Log the first URL being processed to verify it's the correct starting point
				if it.d == 0 {
					fmt.Fprintf(os.Stderr, "DEBUG: Processing initial URL (depth 0): %s\n", pageURL)
				}

				mu.Lock()
				if visited[pageURL] { mu.Unlock(); return }
				visited[pageURL] = true
				results[pageURL] = true
				mu.Unlock()

				req, err := http.NewRequest(http.MethodGet, pageURL, nil)
				if err != nil { return }
				
				// Add custom headers to the request (but remove Accept-Encoding and caching headers)
				headersMutex.Lock()
				headersCopy := make(map[string]string)
				for headerName, headerValue := range customHeaders {
					headersCopy[headerName] = headerValue
				}
				headersMutex.Unlock()
				
				for headerName, headerValue := range headersCopy {
					if headerName != "Accept-Encoding" && headerName != "If-Modified-Since" && headerName != "Cache-Control" {
						req.Header.Set(headerName, headerValue)
					}
				}
				
				// Debug logging for authentication headers
				if len(headersCopy) > 0 {
					fmt.Fprintf(os.Stderr, "DEBUG: Setting %d custom headers for request to %s\n", len(headersCopy), pageURL)
					for name, value := range headersCopy {
						if name == "Cookie" || name == "Authorization" || name == "X-API-Key" {
							fmt.Fprintf(os.Stderr, "DEBUG: Auth header %s: %s\n", name, value)
						}
					}
				}
				
				resp, err := client.Do(req)
				if err != nil { 
					fmt.Fprintf(os.Stderr, "DEBUG: Request failed for %s: %v\n", pageURL, err)
					return 
				}
				
				// Small delay to be respectful to the server
				time.Sleep(50 * time.Millisecond)
				status := resp.StatusCode
				fmt.Fprintf(os.Stderr, "DEBUG: Response status %d for %s\n", status, pageURL)
				
				// Check for redirects
				if resp.Request.URL.String() != pageURL {
					fmt.Fprintf(os.Stderr, "DEBUG: URL was redirected from %s to %s\n", pageURL, resp.Request.URL.String())
				}
				
				if status == http.StatusNotFound {
					resp.Body.Close()
					return
				}
				builder := new(strings.Builder)
				buf := make([]byte, 16384)
				for {
					n, er := resp.Body.Read(buf)
					if n > 0 { builder.Write(buf[:n]) }
					if er != nil { break }
					if builder.Len() > 2*1024*1024 { break }
				}
				resp.Body.Close()

				page, _ := url.Parse(pageURL)
				body := builder.String()
				
				fmt.Fprintf(os.Stderr, "DEBUG: Extracted %d bytes of content from %s\n", len(body), pageURL)
				
				// Log the first 500 characters of content for the initial URL to see what's actually being retrieved
				if it.d == 0 {
					contentPreview := body
					if len(contentPreview) > 500 {
						contentPreview = contentPreview[:500] + "..."
					}
					fmt.Fprintf(os.Stderr, "DEBUG: Initial URL content preview: %s\n", contentPreview)
				}
				
				// Check if this URL should be blacklisted
				if isBlacklisted(pageURL) {
					fmt.Fprintf(os.Stderr, "Skipping blacklisted URL: %s\n", pageURL)
					resp.Body.Close()
					return
				}
				
				// Extract URLs (existing logic)
				urlsFound := 0
				for _, re := range regexes {
					matches := re.FindAllStringSubmatch(body, -1)
					for _, m := range matches {
						candidate := ""
						if len(m) >= 2 { candidate = m[1] } else if len(m) == 1 { candidate = m[0] }
						abs := resolve(candidate, page)
						if abs == "" { continue }
						
						// Check if URL should be blacklisted before adding to queue
						if isBlacklisted(abs) {
							continue
						}
						
						mu.Lock()
						if !results[abs] && len(results) < maxPages {
							results[abs] = true
							pending.Add(1)
							jobs <- item{u: abs, d: it.d + 1}
							fmt.Fprintf(os.Stderr, "DEBUG: Added URL to crawl queue (depth %d): %s\n", it.d + 1, abs)
							urlsFound++
						}
						mu.Unlock()
					}
				}
				
				// Log how many URLs were found from this page
				if it.d == 0 {
					fmt.Fprintf(os.Stderr, "DEBUG: Found %d URLs from initial page %s\n", urlsFound, pageURL)
				}

				// Extract form fields
				formMatches := formPattern.FindAllStringSubmatch(body, -1)
				for _, match := range formMatches {
					if len(match) >= 2 {
						formTag := match[0]
						formContent := match[1]
						
						// Extract action and method from form tag
						actionPattern := regexp.MustCompile(`(?i)action\s*=\s*["']([^"']*)["']`)
						methodPattern := regexp.MustCompile(`(?i)method\s*=\s*["']([^"']*)["']`)
						
						actionMatch := actionPattern.FindStringSubmatch(formTag)
						methodMatch := methodPattern.FindStringSubmatch(formTag)
						
						action := ""
						method := "GET" // default
						
						if len(actionMatch) >= 2 {
							action = actionMatch[1]
						}
						if len(methodMatch) >= 2 {
							method = strings.ToUpper(methodMatch[1])
						}
						
						// Extract input fields from form
						inputMatches := inputPattern.FindAllStringSubmatch(formContent, -1)
						for _, inputMatch := range inputMatches {
							if len(inputMatch) >= 2 {
								dataMu.Lock()
								formFields = append(formFields, FormField{
									URL:      pageURL,
									Method:   method,
									Action:   action,
									Name:     inputMatch[1],
									Type:     "text", // default type
									Value:    "",
									Required: strings.Contains(inputMatch[0], "required"),
								})
								dataMu.Unlock()
							}
						}
					}
				}

				// Extract hidden fields
				hiddenMatches := hiddenPattern.FindAllStringSubmatch(body, -1)
				for _, match := range hiddenMatches {
					if len(match) >= 3 {
						dataMu.Lock()
						hiddenFields = append(hiddenFields, HiddenField{
							URL:   pageURL,
							Name:  match[1],
							Value: match[2],
						})
						dataMu.Unlock()
					}
				}

				// Extract JavaScript APIs
				for _, jsPattern := range jsAPIPatterns {
					jsMatches := jsPattern.FindAllStringSubmatch(body, -1)
					for _, match := range jsMatches {
						if len(match) >= 2 {
							endpoint := match[1]
							abs := resolve(endpoint, page)
							if abs != "" {
								dataMu.Lock()
								jsAPIs = append(jsAPIs, JavaScriptAPI{
									URL:      pageURL,
									Method:   "POST", // Assume POST for JS APIs
									Endpoint: abs,
								})
								dataMu.Unlock()
							}
						}
					}
				}

				// Extract POST endpoints from forms
				postFormPattern := regexp.MustCompile(`(?i)<form[^>]*method\s*=\s*["']post["'][^>]*action\s*=\s*["']([^"']*)["'][^>]*>`)
				postMatches := postFormPattern.FindAllStringSubmatch(body, -1)
				for _, match := range postMatches {
					if len(match) >= 2 {
						action := match[1]
						abs := resolve(action, page)
						if abs != "" {
							dataMu.Lock()
							postEndpoints = append(postEndpoints, POSTEndpoint{
								URL:      pageURL,
								Endpoint: abs,
							})
							dataMu.Unlock()
						}
					}
				}
			}(it)
		}
	}

	// Increase concurrency since we're not having session issues
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go worker()
	}

	pending.Add(1)
	jobs <- item{u: startURL, d: 0}
	go func() { pending.Wait(); close(jobs) }()
	wg.Wait()

	urls := make([]string, 0, len(results))
	for u := range results { urls = append(urls, u) }

	return &CrawlResult{
		URLs:           urls,
		FormFields:     formFields,
		JavaScriptAPIs: jsAPIs,
		HiddenFields:   hiddenFields,
		POSTEndpoints:  postEndpoints,
	}, nil
}

