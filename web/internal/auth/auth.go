package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"vidusec/web/internal/database"
	"vidusec/web/internal/session"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	db            *database.DB
	sessionService *session.Service
	blacklist     map[string]time.Time // JTI -> expiration time
	blacklistMux  sync.RWMutex
}

type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=20"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type AuthResponse struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id,omitempty"`
	User      *database.User `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
}

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidPassword   = errors.New("invalid password")
	ErrUserExists        = errors.New("user already exists")
	ErrInvalidToken      = errors.New("invalid token")
)

const (
	TokenExpiration = 24 * time.Hour
	JWTIssuer       = "vidusec"
	JWTAudience     = "vidusec-api"
)

// getJWTSecret returns the JWT secret from environment variable or generates a secure random one
func getJWTSecret() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// Generate a cryptographically secure random secret
		// WARNING: In production, always set JWT_SECRET environment variable
		randomBytes := make([]byte, 32) // 256-bit secret
		if _, err := rand.Read(randomBytes); err != nil {
			// Fallback to a time-based secret if crypto/rand fails (should never happen)
			panic("Failed to generate secure JWT secret: " + err.Error())
		}
		secret = hex.EncodeToString(randomBytes)
		fmt.Println("⚠️  WARNING: Using auto-generated JWT secret. Set JWT_SECRET environment variable in production!")
	}
	return secret
}

func NewService(db *database.DB, sessionService *session.Service) *Service {
	service := &Service{
		db:            db,
		sessionService: sessionService,
		blacklist:     make(map[string]time.Time),
	}
	
	// Start cleanup goroutine for expired blacklisted tokens
	go service.cleanupBlacklist()
	
	return service
}

// Register creates a new user
func (s *Service) Register(req *RegisterRequest) (*AuthResponse, error) {
	// Check if user already exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ? OR email = ?", 
		req.Username, req.Email).Scan(&count)
	if err != nil {
		return nil, err
	}
	
	if count > 0 {
		return nil, ErrUserExists
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user
	result, err := s.db.Exec(`
		INSERT INTO users (username, email, password_hash) 
		VALUES (?, ?, ?)`,
		req.Username, req.Email, string(hashedPassword))
	if err != nil {
		return nil, err
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	// Get created user
	user, err := s.GetUserByID(int(userID))
	if err != nil {
		return nil, err
	}

	// Generate token
	token, expiresAt, err := s.GenerateToken(user)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		Token:     token,
		User:      user,
		ExpiresAt: expiresAt,
	}, nil
}

// Login authenticates a user
func (s *Service) Login(req *LoginRequest) (*AuthResponse, error) {
	// Get user by username
	user, err := s.GetUserByUsername(req.Username)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		return nil, ErrInvalidPassword
	}

	// Generate JWT token for API authentication
	token, expiresAt, err := s.GenerateToken(user)
	if err != nil {
		return nil, err
	}

	// Create session for web authentication
	session, err := s.sessionService.CreateSession(user.ID, user.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}

	return &AuthResponse{
		Token:     token,
		SessionID: session.ID,
		User:      user,
		ExpiresAt: expiresAt,
	}, nil
}

// GetUserByID retrieves a user by ID
func (s *Service) GetUserByID(id int) (*database.User, error) {
	user := &database.User{}
	err := s.db.QueryRow(`
		SELECT id, username, email, password_hash, role, created_at, updated_at 
		FROM users WHERE id = ?`, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, 
		&user.Role, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByUsername retrieves a user by username
func (s *Service) GetUserByUsername(username string) (*database.User, error) {
	user := &database.User{}
	err := s.db.QueryRow(`
		SELECT id, username, email, password_hash, role, created_at, updated_at 
		FROM users WHERE username = ?`, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, 
		&user.Role, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GenerateToken creates a JWT token for a user
func (s *Service) GenerateToken(user *database.User) (string, time.Time, error) {
	expiresAt := time.Now().Add(TokenExpiration)
	now := time.Now()
	
	// Generate unique JWT ID for token tracking
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate JTI: %v", err)
	}
	jti := hex.EncodeToString(jtiBytes)
	
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    JWTIssuer,
			Audience:  []string{JWTAudience},
			ID:        jti, // JWT ID for token tracking
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(getJWTSecret()))
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expiresAt, nil
}

// ValidateToken validates a JWT token and returns the claims
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// CRITICAL: Validate the signing method to prevent algorithm confusion attacks
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		
		// CRITICAL: Explicitly reject 'none' algorithm
		if token.Header["alg"] == "none" {
			return nil, fmt.Errorf("'none' algorithm not allowed")
		}
		
		return []byte(getJWTSecret()), nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Validate critical claims
		if err := s.validateClaims(claims); err != nil {
			return nil, err
		}
		return claims, nil
	}

	return nil, ErrInvalidToken
}

// validateClaims validates the JWT claims for security
func (s *Service) validateClaims(claims *Claims) error {
	// Check if token is blacklisted
	if s.isTokenBlacklisted(claims.ID) {
		return fmt.Errorf("token has been revoked")
	}
	
	// Validate issuer
	if claims.Issuer != JWTIssuer {
		return fmt.Errorf("invalid issuer: %s", claims.Issuer)
	}
	
	// Validate audience
	if len(claims.Audience) == 0 || claims.Audience[0] != JWTAudience {
		return fmt.Errorf("invalid audience")
	}
	
	// Validate expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return fmt.Errorf("token has expired")
	}
	
	// Validate not before
	if claims.NotBefore != nil && claims.NotBefore.Time.After(time.Now()) {
		return fmt.Errorf("token not yet valid")
	}
	
	// Validate issued at (should not be in the future)
	if claims.IssuedAt != nil && claims.IssuedAt.Time.After(time.Now().Add(time.Minute)) {
		return fmt.Errorf("token issued in the future")
	}
	
	return nil
}

// isTokenBlacklisted checks if a token JTI is in the blacklist
func (s *Service) isTokenBlacklisted(jti string) bool {
	s.blacklistMux.RLock()
	defer s.blacklistMux.RUnlock()
	
	expiration, exists := s.blacklist[jti]
	if !exists {
		return false
	}
	
	// If the blacklisted token has expired, consider it not blacklisted
	if time.Now().After(expiration) {
		return false
	}
	
	return true
}

// blacklistToken adds a token JTI to the blacklist
func (s *Service) blacklistToken(jti string, expiration time.Time) {
	s.blacklistMux.Lock()
	defer s.blacklistMux.Unlock()
	
	s.blacklist[jti] = expiration
}

// cleanupBlacklist removes expired tokens from the blacklist
func (s *Service) cleanupBlacklist() {
	ticker := time.NewTicker(time.Hour) // Clean up every hour
	defer ticker.Stop()
	
	for range ticker.C {
		s.blacklistMux.Lock()
		now := time.Now()
		for jti, expiration := range s.blacklist {
			if now.After(expiration) {
				delete(s.blacklist, jti)
			}
		}
		s.blacklistMux.Unlock()
	}
}

// Logout invalidates the user's session and blacklists the JWT token
func (s *Service) Logout(sessionID string, tokenString string) error {
	// Invalidate session
	if sessionID != "" {
		if err := s.sessionService.InvalidateSession(sessionID); err != nil {
			return err
		}
	}
	
	// Blacklist JWT token if provided
	if tokenString != "" {
		claims, err := s.ValidateToken(tokenString)
		if err == nil && claims.ID != "" {
			// Blacklist the token until its natural expiration
			s.blacklistToken(claims.ID, claims.ExpiresAt.Time)
		}
	}
	
	return nil
}

// LogoutAllSessions invalidates all sessions for a user
func (s *Service) LogoutAllSessions(userID int) error {
	return s.sessionService.InvalidateUserSessions(userID)
}
