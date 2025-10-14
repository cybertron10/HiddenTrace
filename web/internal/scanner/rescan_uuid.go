package scanner

import (
    "encoding/json"
    "log"
    "os"
    "path/filepath"
)

// RescanScanByUUID restarts a scan by UUID with authorization check
func (s *Service) RescanScanByUUID(scanUUID string, userID int, req *ScanRequest) (*ScanResponse, error) {
	// Verify ownership first
	err := s.VerifyScanOwnership(scanUUID, userID)
	if err != nil {
		return nil, err
	}

	// Get the scan to get its ID
	scan, err := s.GetScanByUUID(scanUUID, userID)
	if err != nil {
		return nil, err
	}

	// Set the target URL in the request for the rescan
	req.TargetURL = scan.TargetURL
	
	// Get original headers from the scan results before deleting them
	originalHeaders, err := s.getOriginalHeadersFromScan(scanUUID)
	if err != nil {
		log.Printf("Warning: Could not retrieve original headers for rescan: %v", err)
	} else if len(originalHeaders) > 0 {
		// Use original headers for rescan
		req.Headers = originalHeaders
		log.Printf("Rescan will use original headers: %v", originalHeaders)
	}
	
	log.Printf("Rescan request prepared - URL: %s, MaxDepth: %d, MaxPages: %d, Headers: %d", req.TargetURL, req.MaxDepth, req.MaxPages, len(req.Headers))

	// Reset scan status and progress
	log.Printf("Resetting scan status for UUID %s", scanUUID)
	_, err = s.db.Exec(`
		UPDATE scans SET status = 'pending', progress = 0, started_at = NULL, completed_at = NULL 
		WHERE scan_uuid = ? AND user_id = ?`,
		scanUUID, userID)
	if err != nil {
		log.Printf("Failed to reset scan status: %v", err)
		return nil, err
	}

	// Delete old results
	log.Printf("Deleting old results for UUID %s", scanUUID)
	_, err = s.db.Exec(`DELETE FROM scan_results WHERE scan_uuid = ?`, scanUUID)
	if err != nil {
		log.Printf("Failed to delete old results: %v", err)
		return nil, err
	}

	// Delete old statistics
	log.Printf("Deleting old statistics for UUID %s", scanUUID)
	_, err = s.db.Exec(`DELETE FROM scan_statistics WHERE scan_uuid = ?`, scanUUID)
	if err != nil {
		log.Printf("Failed to delete old statistics: %v", err)
		return nil, err
	}

	// Delete old files
	log.Printf("Deleting old files for UUID %s", scanUUID)
	_, err = s.db.Exec(`DELETE FROM scan_files WHERE scan_uuid = ?`, scanUUID)
	if err != nil {
		log.Printf("Failed to delete old files: %v", err)
		return nil, err
	}

    // Remove scan directory on filesystem (reports, wordlists, progress, etc.)
    scanDir := filepath.Join("data", "scans", scanUUID)
    if err := os.RemoveAll(scanDir); err != nil {
        log.Printf("Warning: Failed to delete scan directory %s: %v", scanDir, err)
        // don't fail the rescan if directory removal fails
    } else {
        log.Printf("Deleted scan directory: %s", scanDir)
    }

	// Start scan in background
	log.Printf("Starting background scan for ID %d, UUID %s", scan.ID, scanUUID)
	go s.runScan(scan.ID, scanUUID, req)

	log.Printf("Rescan initiated successfully for scan %d (UUID: %s)", scan.ID, scanUUID)
	return &ScanResponse{
		ScanID:  scan.ID,
		Status:  "pending",
		Message: "Rescan initiated successfully",
	}, nil
}

// getOriginalHeadersFromScan retrieves the original headers used in a scan
func (s *Service) getOriginalHeadersFromScan(scanUUID string) (map[string]string, error) {
	// Get a sample of headers from the scan results to extract the original custom headers
	rows, err := s.db.Query(`
		SELECT headers 
		FROM scan_results 
		WHERE scan_uuid = ? AND headers IS NOT NULL AND headers != '{}' AND headers != 'null'
		LIMIT 1`,
		scanUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		// No headers found, return empty map
		return make(map[string]string), nil
	}

	var headersJSON string
	if err := rows.Scan(&headersJSON); err != nil {
		return nil, err
	}

	// Parse the headers JSON
	var headers map[string]interface{}
	if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
		return nil, err
	}

	// Convert to map[string]string and filter out default headers
	originalHeaders := make(map[string]string)
	for key, value := range headers {
		if valueStr, ok := value.(string); ok {
			// Filter out default headers that are automatically added
			if key != "User-Agent" && key != "Content-Type" && key != "Accept" && 
			   key != "Accept-Language" && key != "Accept-Encoding" && key != "Connection" {
				originalHeaders[key] = valueStr
			}
		}
	}

	log.Printf("Retrieved original headers for rescan: %v", originalHeaders)
	return originalHeaders, nil
}
