package database

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	*sql.DB
}

// Initialize creates and initializes the database
func Initialize() (*DB, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll("data", 0755); err != nil {
		return nil, err
	}

	// Open SQLite database
	db, err := sql.Open("sqlite3", "data/vidusec.db")
	if err != nil {
		return nil, err
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	database := &DB{db}

	// Create tables
	if err := database.createTables(); err != nil {
		return nil, err
	}

	// Run migrations
	if err := RunMigrations(db); err != nil {
		return nil, err
	}

	log.Println("✅ Database initialized successfully")
	return database, nil
}

// createTables creates all necessary tables
func (db *DB) createTables() error {
	queries := []string{
		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT DEFAULT 'user',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Scans table
		`CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_uuid TEXT UNIQUE NOT NULL,
			user_id INTEGER NOT NULL,
			target_url TEXT NOT NULL,
			max_depth INTEGER DEFAULT 10,
			max_pages INTEGER DEFAULT 20000,
			status TEXT DEFAULT 'pending',
			progress INTEGER DEFAULT 0,
			started_at DATETIME,
			completed_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users (id)
		)`,

		// Scan results table
		`CREATE TABLE IF NOT EXISTS scan_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			scan_uuid TEXT NOT NULL,
			endpoint_type TEXT NOT NULL,
			url TEXT NOT NULL,
			method TEXT NOT NULL,
			parameters TEXT,
			form_data TEXT,
			headers TEXT,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans (id),
			FOREIGN KEY (scan_uuid) REFERENCES scans (scan_uuid)
		)`,

		// Scan statistics table
		`CREATE TABLE IF NOT EXISTS scan_statistics (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			scan_uuid TEXT NOT NULL,
			total_endpoints INTEGER DEFAULT 0,
			get_endpoints INTEGER DEFAULT 0,
			post_endpoints INTEGER DEFAULT 0,
			js_endpoints INTEGER DEFAULT 0,
			total_parameters INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans (id),
			FOREIGN KEY (scan_uuid) REFERENCES scans (scan_uuid)
		)`,

		// Scan files table (for storing generated files)
		`CREATE TABLE IF NOT EXISTS scan_files (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			scan_uuid TEXT NOT NULL,
			file_type TEXT NOT NULL,
			file_path TEXT NOT NULL,
			file_size INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans (id),
			FOREIGN KEY (scan_uuid) REFERENCES scans (scan_uuid)
		)`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return err
		}
	}

	// Create indexes for better performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)",
		"CREATE INDEX IF NOT EXISTS idx_scans_uuid ON scans(scan_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id)",
		"CREATE INDEX IF NOT EXISTS idx_scan_results_scan_uuid ON scan_results(scan_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_scan_results_type ON scan_results(endpoint_type)",
		"CREATE INDEX IF NOT EXISTS idx_scan_files_scan_id ON scan_files(scan_id)",
		"CREATE INDEX IF NOT EXISTS idx_scan_files_scan_uuid ON scan_files(scan_uuid)",
	}

	for _, index := range indexes {
		if _, err := db.Exec(index); err != nil {
			return err
		}
	}

	// Run migrations for existing databases
	return db.runMigrations()
}

// runMigrations handles database schema migrations
func (db *DB) runMigrations() error {
	// Check if role column exists, if not add it
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='role'").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		log.Println("Adding role column to users table...")
		_, err = db.Exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
		if err != nil {
			return err
		}
		log.Println("Role column added successfully")
	}

	// Set existing users (ID 1) as admin if they don't have a role set
	_, err = db.Exec("UPDATE users SET role = 'admin' WHERE id = 1 AND (role IS NULL OR role = 'user')")
	if err != nil {
		log.Printf("Warning: Could not update user 1 to admin role: %v", err)
	}

	return nil
}
