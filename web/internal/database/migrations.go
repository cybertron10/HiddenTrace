package database

import (
	"database/sql"
	"fmt"
	"log"
)

// RunMigrations runs database migrations to update schema
func RunMigrations(db *sql.DB) error {
	log.Println("🔄 Running database migrations...")

	// Check if last_used column exists in sessions table
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) 
		FROM pragma_table_info('sessions') 
		WHERE name = 'last_used'
	`).Scan(&count)
	
	if err != nil {
		return fmt.Errorf("failed to check sessions table schema: %v", err)
	}

	// If last_used column doesn't exist, add it
	if count == 0 {
		log.Println("📝 Adding last_used column to sessions table...")
		
		// Add the last_used column without default (SQLite limitation)
		_, err = db.Exec(`
			ALTER TABLE sessions 
			ADD COLUMN last_used DATETIME
		`)
		if err != nil {
			return fmt.Errorf("failed to add last_used column: %v", err)
		}

		// Update existing sessions to have last_used = created_at
		_, err = db.Exec(`
			UPDATE sessions 
			SET last_used = created_at 
			WHERE last_used IS NULL
		`)
		if err != nil {
			return fmt.Errorf("failed to update existing sessions: %v", err)
		}

		log.Println("✅ Successfully added last_used column to sessions table")
	} else {
		log.Println("✅ last_used column already exists in sessions table")
	}

	// Create index for last_used if it doesn't exist
	_, err = db.Exec("CREATE INDEX IF NOT EXISTS idx_sessions_last_used ON sessions(last_used)")
	if err != nil {
		return fmt.Errorf("failed to create sessions last_used index: %v", err)
	}

	// Check if headers column exists in scans table
	err = db.QueryRow(`
		SELECT COUNT(*) 
		FROM pragma_table_info('scans') 
		WHERE name = 'headers'
	`).Scan(&count)
	
	if err != nil {
		return fmt.Errorf("failed to check scans table schema: %v", err)
	}

	// If headers column doesn't exist, add it
	if count == 0 {
		log.Println("📝 Adding headers column to scans table...")
		
		// Add the headers column
		_, err = db.Exec(`
			ALTER TABLE scans 
			ADD COLUMN headers TEXT
		`)
		if err != nil {
			return fmt.Errorf("failed to add headers column: %v", err)
		}

		log.Println("✅ Successfully added headers column to scans table")
	} else {
		log.Println("✅ headers column already exists in scans table")
	}

	log.Println("✅ Database migrations completed successfully")
	return nil
}
