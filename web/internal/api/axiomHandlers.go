package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// AxiomScanRequest represents the request to start an Axiom scan
type AxiomScanRequest struct {
	ScanUUID string `json:"scan_uuid" binding:"required"`
}

// AxiomScanStatus represents the status of an Axiom scan
type AxiomScanStatus struct {
	ScanUUID string    `json:"scan_uuid"`
	Status   string    `json:"status"` // scanning, completed, error
	Progress int       `json:"progress"`
	Message  string    `json:"message"`
	StartTime time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// AxiomScanResult represents a single XSS finding
type AxiomScanResult struct {
	URL     string `json:"url"`
	Payload string `json:"payload"`
	Result  string `json:"result"`
}

// AxiomScanResponse represents the response with scan results
type AxiomScanResponse struct {
	ScanUUID string            `json:"scan_uuid"`
	Results  []AxiomScanResult `json:"results"`
	Total    int               `json:"total"`
}

// StartAxiomScan starts an Axiom XSS scan
func (h *Handler) StartAxiomScan(c *gin.Context) {
	var request AxiomScanRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scanUUID := c.Param("id")
	if scanUUID != request.ScanUUID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Scan UUID mismatch"})
		return
	}

	// Start Axiom scan in background
	go h.runAxiomScan(scanUUID)

	// Return immediate response
	c.JSON(http.StatusOK, gin.H{
		"message": "Axiom scan started successfully",
		"scan_uuid": scanUUID,
		"status": "scanning",
	})
}

// runAxiomScan executes the actual Axiom scan
func (h *Handler) runAxiomScan(scanUUID string) {
	scanDir := filepath.Join("data", "scans", scanUUID)
	allurlsFile := filepath.Join(scanDir, "allurls.txt")
	statusFile := filepath.Join(scanDir, "axiom_scan_status.json")
    logFile := filepath.Join(scanDir, "axiom_scan.log")

	// Initialize status
	status := AxiomScanStatus{
		ScanUUID:  scanUUID,
		Status:    "scanning",
		Progress:  0,
		Message:   "Preparing Axiom scan...",
		StartTime: time.Now(),
	}
	h.saveAxiomStatus(statusFile, status)

	// Check if allurls.txt exists
	if _, err := os.Stat(allurlsFile); os.IsNotExist(err) {
		status.Status = "error"
		status.Error = "allurls.txt not found. Please run crawling and parameter fuzzing first."
		status.EndTime = &[]time.Time{time.Now()}[0]
		h.saveAxiomStatus(statusFile, status)
		return
	}

	// Update status
	status.Progress = 10
	status.Message = "Starting Axiom scan..."
	h.saveAxiomStatus(statusFile, status)

    // If allurls.txt exists but is empty, fail fast with a clear message
    if fi, err := os.Stat(allurlsFile); err == nil && fi.Size() == 0 {
        status.Status = "error"
        status.Error = "allurls.txt is empty. No URLs to scan."
        status.EndTime = &[]time.Time{time.Now()}[0]
        _ = h.saveAxiomStatus(statusFile, status)
        return
    }

    // Prefer executing via a shell so login/profile PATH customizations are honored
    // and axiom-scan subcommands/modules resolve correctly.
    // We run exactly: axiom-scan allurls.txt -m xss-scan -o xss.txt in scanDir
    shellCmd := fmt.Sprintf("axiom-scan %s -m xss-scan -o %s", "allurls.txt", "xss.txt")

    // Best-effort hint if axiom-scan is not in PATH of the service
    if _, lookErr := exec.LookPath("axiom-scan"); lookErr != nil {
        log.Printf("Warning: axiom-scan not found in PATH for process: %v. Will attempt via shell anyway.", lookErr)
    }

    cmd := exec.Command("bash", "-lc", shellCmd)
    cmd.Dir = scanDir
    cmd.Env = os.Environ()

    // Capture stdout+stderr
    combinedOutput, err := cmd.CombinedOutput()
    // Always write log file for troubleshooting
    _ = ioutil.WriteFile(logFile, combinedOutput, 0644)
    if err != nil {
        log.Printf("Axiom scan failed for scan %s: %v", scanUUID, err)
        // Include a short tail of the output to help the user
        tail := string(combinedOutput)
        if len(tail) > 4000 { // cap to avoid huge responses
            tail = tail[len(tail)-4000:]
        }
        status.Status = "error"
        status.Error = fmt.Sprintf("Axiom scan execution failed: %v\nSee axiom_scan.log for details. Last output:\n%s", err, tail)
        status.EndTime = &[]time.Time{time.Now()}[0]
        _ = h.saveAxiomStatus(statusFile, status)
        return
    }

	// Update status
	status.Progress = 90
	status.Message = "Processing results..."
	h.saveAxiomStatus(statusFile, status)

	// Mark as completed
	status.Status = "completed"
	status.Progress = 100
	status.Message = "Axiom scan completed successfully"
	status.EndTime = &[]time.Time{time.Now()}[0]
	h.saveAxiomStatus(statusFile, status)

	log.Printf("Axiom scan completed for scan %s", scanUUID)
}

// GetAxiomScanStatus returns the current status of an Axiom scan
func (h *Handler) GetAxiomScanStatus(c *gin.Context) {
	scanUUID := c.Param("id")
	scanDir := filepath.Join("data", "scans", scanUUID)
	statusFile := filepath.Join(scanDir, "axiom_scan_status.json")

	// Check if status file exists
	if _, err := os.Stat(statusFile); os.IsNotExist(err) {
		c.JSON(http.StatusOK, gin.H{
			"scan_uuid": scanUUID,
			"status":    "not_started",
			"message":   "Axiom scan not started",
		})
		return
	}

	// Read status file
	data, err := ioutil.ReadFile(statusFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read scan status"})
		return
	}

	var status AxiomScanStatus
	if err := json.Unmarshal(data, &status); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse scan status"})
		return
	}

	c.JSON(http.StatusOK, status)
}

// GetAxiomScanResults returns the results of an Axiom scan
func (h *Handler) GetAxiomScanResults(c *gin.Context) {
	scanUUID := c.Param("id")
	scanDir := filepath.Join("data", "scans", scanUUID)
	outputFile := filepath.Join(scanDir, "xss.txt")

	// Check if results file exists
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		c.JSON(http.StatusOK, gin.H{
			"scan_uuid": scanUUID,
			"results":   []AxiomScanResult{},
			"total":     0,
		})
		return
	}

	// Read results file
	data, err := ioutil.ReadFile(outputFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read scan results"})
		return
	}

	// Parse results
	results := h.parseAxiomResults(string(data))

	response := AxiomScanResponse{
		ScanUUID: scanUUID,
		Results:  results,
		Total:    len(results),
	}

	c.JSON(http.StatusOK, response)
}

// parseAxiomResults parses the output from axiom-scan
func (h *Handler) parseAxiomResults(content string) []AxiomScanResult {
    // Display every non-empty line from xss.txt as a result, since output
    // format can vary by module/version. If a URL appears in the line,
    // extract and show it; otherwise leave URL empty and show raw line.
    var results []AxiomScanResult

    lines := strings.Split(content, "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }

        urlInLine := ""
        for _, part := range strings.Fields(line) {
            if strings.HasPrefix(part, "http://") || strings.HasPrefix(part, "https://") {
                urlInLine = strings.Trim(part, ",;\"'()")
                break
            }
        }

        results = append(results, AxiomScanResult{
            URL:    urlInLine,
            Result: line,
        })
    }

    return results
}

// saveAxiomStatus saves the Axiom scan status to a file
func (h *Handler) saveAxiomStatus(filename string, status AxiomScanStatus) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0644)
}
