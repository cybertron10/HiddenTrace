package session

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"HiddenTrace/web/internal/database"
)

type Service struct {
	db *database.DB
}

type Session struct {
	ID        string    `json:"id"`
	UserID    int       `json:"user_id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	LastUsed  time.Time `json:"last_used"`
	IsActive  bool      `json:"is_active"`
}

const (
	SessionExpiration = 24 * time.Hour
	SessionIDLength   = 32 // 32 bytes = 64 hex characters
	IdleTimeout       = 2 * time.Hour // Session expires after 2 hours of inactivity
	RotationInterval  = 30 * time.Minute // Rotate session ID every 30 minutes
)

func NewService(db *database.DB) *Service {
	return &Service{db: db}
}

// Initialize creates the sessions table
func (s *Service) Initialize() error {
	query := `
		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			username TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			last_used DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_active BOOLEAN DEFAULT 1,
			FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
		)`
	
	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create sessions table: %v", err)
	}

	// Create index for better performance
	_, err = s.db.Exec("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")
	if err != nil {
		return fmt.Errorf("failed to create sessions index: %v", err)
	}

	_, err = s.db.Exec("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
	if err != nil {
		return fmt.Errorf("failed to create sessions expiration index: %v", err)
	}

	// Try to create last_used index, but don't fail if column doesn't exist yet
	// (migrations will handle adding the column)
	_, err = s.db.Exec("CREATE INDEX IF NOT EXISTS idx_sessions_last_used ON sessions(last_used)")
	if err != nil {
		log.Printf("Warning: Could not create last_used index (column may not exist yet): %v", err)
		// Don't return error here - migrations will handle it
	}

	log.Println("Session service initialized successfully")
	return nil
}

// generateSessionID creates a cryptographically secure random session ID
func (s *Service) generateSessionID() (string, error) {
	bytes := make([]byte, SessionIDLength)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateSession creates a new session for a user
func (s *Service) CreateSession(userID int, username string) (*Session, error) {
	sessionID, err := s.generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %v", err)
	}

	now := time.Now()
	expiresAt := now.Add(SessionExpiration)

	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		Username:  username,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		LastUsed:  now,
		IsActive:  true,
	}

	_, err = s.db.Exec(`
		INSERT INTO sessions (id, user_id, username, created_at, expires_at, last_used, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sessionID, userID, username, now, expiresAt, now, true)
	
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}

	log.Printf("Created session %s for user %d (%s)", sessionID, userID, username)
	return session, nil
}

// GetSession retrieves a session by ID with rotation and idle timeout checks
func (s *Service) GetSession(sessionID string) (*Session, error) {
	session := &Session{}
	err := s.db.QueryRow(`
		SELECT id, user_id, username, created_at, expires_at, last_used, is_active
		FROM sessions
		WHERE id = ? AND is_active = 1`,
		sessionID).Scan(
		&session.ID, &session.UserID, &session.Username,
		&session.CreatedAt, &session.ExpiresAt, &session.LastUsed, &session.IsActive)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found or expired")
		}
		return nil, fmt.Errorf("failed to get session: %v", err)
	}

	now := time.Now()

	// Check if session is expired
	if now.After(session.ExpiresAt) {
		// Mark session as inactive
		s.InvalidateSession(sessionID)
		return nil, fmt.Errorf("session expired")
	}

	// Check idle timeout
	if now.Sub(session.LastUsed) > IdleTimeout {
		// Mark session as inactive due to idle timeout
		s.InvalidateSession(sessionID)
		return nil, fmt.Errorf("session expired due to inactivity")
	}

	// Update last used timestamp
	_, err = s.db.Exec("UPDATE sessions SET last_used = ? WHERE id = ?", now, sessionID)
	if err != nil {
		log.Printf("Warning: Failed to update session last_used: %v", err)
	}
	session.LastUsed = now

	return session, nil
}

// InvalidateSession marks a session as inactive
func (s *Service) InvalidateSession(sessionID string) error {
	_, err := s.db.Exec(`
		UPDATE sessions 
		SET is_active = 0 
		WHERE id = ?`,
		sessionID)
	
	if err != nil {
		return fmt.Errorf("failed to invalidate session: %v", err)
	}
	
	log.Printf("Invalidated session %s", sessionID)
	return nil
}

// RotateSession creates a new session ID for an existing session (prevents session fixation)
func (s *Service) RotateSession(oldSessionID string) (*Session, error) {
	// Get the current session
	oldSession, err := s.GetSession(oldSessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current session: %v", err)
	}

	// Generate new session ID
	newSessionID, err := s.generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new session ID: %v", err)
	}

	now := time.Now()
	expiresAt := now.Add(SessionExpiration)

	// Create new session
	newSession := &Session{
		ID:        newSessionID,
		UserID:    oldSession.UserID,
		Username:  oldSession.Username,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		LastUsed:  now,
		IsActive:  true,
	}

	// Insert new session
	_, err = s.db.Exec(`
		INSERT INTO sessions (id, user_id, username, created_at, expires_at, last_used, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		newSessionID, oldSession.UserID, oldSession.Username, now, expiresAt, now, true)
	
	if err != nil {
		return nil, fmt.Errorf("failed to create new session: %v", err)
	}

	// Invalidate old session
	err = s.InvalidateSession(oldSessionID)
	if err != nil {
		// If we can't invalidate the old session, at least clean up the new one
		s.InvalidateSession(newSessionID)
		return nil, fmt.Errorf("failed to invalidate old session: %v", err)
	}

	log.Printf("Rotated session from %s to %s for user %d", oldSessionID, newSessionID, oldSession.UserID)
	return newSession, nil
}

// InvalidateUserSessions invalidates all sessions for a specific user
func (s *Service) InvalidateUserSessions(userID int) error {
	_, err := s.db.Exec(`
		UPDATE sessions 
		SET is_active = 0 
		WHERE user_id = ?`,
		userID)
	
	if err != nil {
		return fmt.Errorf("failed to invalidate user sessions: %v", err)
	}

	log.Printf("Invalidated all sessions for user %d", userID)
	return nil
}

// CleanupExpiredSessions removes expired sessions from the database
func (s *Service) CleanupExpiredSessions() error {
	result, err := s.db.Exec(`
		DELETE FROM sessions 
		WHERE expires_at < ? OR is_active = 0`,
		time.Now())
	
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %v", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Printf("Cleaned up %d expired sessions", rowsAffected)
	}

	return nil
}

// GetUserSessions returns all active sessions for a user
func (s *Service) GetUserSessions(userID int) ([]*Session, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, username, created_at, expires_at, is_active
		FROM sessions
		WHERE user_id = ? AND is_active = 1 AND expires_at > ?
		ORDER BY created_at DESC`,
		userID, time.Now())
	
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %v", err)
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		session := &Session{}
		err := rows.Scan(
			&session.ID, &session.UserID, &session.Username,
			&session.CreatedAt, &session.ExpiresAt, &session.IsActive)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %v", err)
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}
