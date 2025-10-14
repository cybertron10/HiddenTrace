package paramsmapper

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

func chunkParams(params []string, chunkSize int) [][]string {
	var chunks [][]string
	for i := 0; i < len(params); i += chunkSize {
		end := i + chunkSize
		if end > len(params) {
			end = len(params)
		}
		chunks = append(chunks, params[i:end])
	}
	return chunks
}

// LoadWordlist loads parameters from a wordlist file
func LoadWordlist(wordlist string) []string {
	file, err := os.Open(wordlist)
	if err != nil {
		logger.Error("Failed to open wordlist", "error", err)
		os.Exit(1)
	}
	defer file.Close()

	var params []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		params = append(params, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		logger.Error("Failed to read wordlist", "error", err)
		os.Exit(1)
	}

	return params
}

func randomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	}
	return userAgents[rand.Intn(len(userAgents))]
}

func countReflections(params url.Values, body []byte) int {
	count := 0
	for _, values := range params {
		for _, value := range values {
			if bytes.Contains(body, []byte(value)) {
				count++
			}
		}
	}
	return count
}

func createHTTPClient(timeout int) *http.Client {
	if ignoreCertErrors {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		return &http.Client{Transport: tr, Timeout: time.Duration(timeout) * time.Second}
	}
	return &http.Client{}
}

func generateParams(params []string) url.Values {
	values := url.Values{}
	for _, param := range params {
        values.Set(param, createParamScopedToken(param))
	}
	return values
}

// createParamScopedToken generates a token that embeds the parameter name to
// make reflections attributable to a specific parameter and reduce false positives.
// Example: __VIDU_paramName_ab12CD34__
func createParamScopedToken(param string) string {
    sanitized := sanitizeParamName(param)
    if sanitized == "" {
        sanitized = "p"
    }
    // Alphanumeric-only token (no separators) to satisfy strict validators
    return "VIDU" + sanitized + randomString(8)
}

// sanitizeParamName converts a parameter name to a safe identifier consisting
// of letters and digits only (no underscores), and caps the length for brevity.
func sanitizeParamName(name string) string {
    if name == "" {
        return ""
    }
    // Limit to 32 characters to keep tokens concise
    const maxLen = 32
    var b strings.Builder
    for _, r := range name {
        if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
            b.WriteRune(r)
        }
        if b.Len() >= maxLen {
            break
        }
    }
    return b.String()
}

func extractFormParams(body []byte) []string {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		logger.Error("Failed to parse HTML", "error", err)
	}

	var formParams []string
	doc.Find("input, select, textarea").Each(func(i int, s *goquery.Selection) {
		name, exists := s.Attr("name")
		if exists {
			formParams = append(formParams, name)
		}
	})
	return formParams
}

func randomString(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// LoadHeaders loads custom headers from a file
func LoadHeaders(headersFile string) map[string]string {
	headers := make(map[string]string)
	
	file, err := os.Open(headersFile)
	if err != nil {
		logger.Error("Failed to open headers file", "error", err)
		return headers
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headerName := strings.TrimSpace(parts[0])
			headerValue := strings.TrimSpace(parts[1])
			headers[headerName] = headerValue
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Error("Failed to read headers file", "error", err)
	}

	return headers
}
