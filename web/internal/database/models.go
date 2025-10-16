package database

import (
	"database/sql/driver"
	"encoding/json"
	"time"
)

// User represents a user in the system
type User struct {
	ID           int       `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	Role         string    `json:"role" db:"role"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// Scan represents a security scan
type Scan struct {
	ID         int                    `json:"id" db:"id"`
	ScanUUID   string                 `json:"scan_uuid" db:"scan_uuid"`
	UserID     int                    `json:"user_id" db:"user_id"`
	TargetURL  string                 `json:"target_url" db:"target_url"`
	MaxDepth   int                    `json:"max_depth" db:"max_depth"`
	MaxPages   int                    `json:"max_pages" db:"max_pages"`
	Headers    map[string]interface{} `json:"headers" db:"headers"`
	Status     string                 `json:"status" db:"status"` // pending, running, completed, failed
	Progress   int                    `json:"progress" db:"progress"`
	StartedAt  *time.Time             `json:"started_at" db:"started_at"`
	CompletedAt *time.Time            `json:"completed_at" db:"completed_at"`
	CreatedAt  time.Time              `json:"created_at" db:"created_at"`
}

// ScanResult represents a discovered endpoint
type ScanResult struct {
	ID          int                    `json:"id" db:"id"`
	ScanID      int                    `json:"scan_id" db:"scan_id"`
	ScanUUID    string                 `json:"scan_uuid" db:"scan_uuid"`
	EndpointType string                `json:"endpoint_type" db:"endpoint_type"` // get, post, js_api
	URL         string                 `json:"url" db:"url"`
	Method      string                 `json:"method" db:"method"`
	Parameters  map[string]interface{} `json:"parameters" db:"parameters"`
	FormData    map[string]interface{} `json:"form_data" db:"form_data"`
	Headers     map[string]interface{} `json:"headers" db:"headers"`
	Description string                 `json:"description" db:"description"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
}

// ScanStatistics represents scan summary statistics
type ScanStatistics struct {
	ID              int       `json:"id" db:"id"`
	ScanID          int       `json:"scan_id" db:"scan_id"`
	ScanUUID        string    `json:"scan_uuid" db:"scan_uuid"`
	TotalEndpoints  int       `json:"total_endpoints" db:"total_endpoints"`
	GETEndpoints    int       `json:"get_endpoints" db:"get_endpoints"`
	POSTEndpoints   int       `json:"post_endpoints" db:"post_endpoints"`
	JSEndpoints     int       `json:"js_endpoints" db:"js_endpoints"`
	TotalParameters int       `json:"total_parameters" db:"total_parameters"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
}

// ScanFile represents a generated file from a scan
type ScanFile struct {
	ID       int       `json:"id" db:"id"`
	ScanID   int       `json:"scan_id" db:"scan_id"`
	ScanUUID string    `json:"scan_uuid" db:"scan_uuid"`
	FileType string    `json:"file_type" db:"file_type"` // json, txt, csv
	FilePath string    `json:"file_path" db:"file_path"`
	FileSize int64     `json:"file_size" db:"file_size"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// JSONMap is a custom type for JSON fields in database
type JSONMap map[string]interface{}

// Value implements the driver.Valuer interface for JSONMap
func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan implements the sql.Scanner interface for JSONMap
func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	
	return json.Unmarshal(bytes, j)
}

// DashboardStats represents dashboard statistics
type DashboardStats struct {
	TotalScans      int `json:"total_scans"`
	CompletedScans  int `json:"completed_scans"`
	RunningScans    int `json:"running_scans"`
	TotalEndpoints  int `json:"total_endpoints"`
    AxiomResults    int `json:"axiom_results"`
    YetToScan       int `json:"yet_to_scan"`
	RecentScans     []Scan `json:"recent_scans"`
}
