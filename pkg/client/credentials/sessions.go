// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
)

const (
	sessionsFileName = "sessions.json"
	sessionDirLength = 12 // Length of random hex string for session directories
)

// SessionInfo holds information about a session for a specific server
type SessionInfo struct {
	Dir       string    `json:"dir"`
	CreatedAt time.Time `json:"created_at"`
	ServerURL string    `json:"server_url,omitempty"` // Stored for reference
}

// SessionsConfig holds the mapping of servers to session directories
type SessionsConfig struct {
	Sessions map[string]*SessionInfo `json:"sessions"`
	Default  string                  `json:"default,omitempty"`
}

// GetConfigDir returns the carabiner config directory path
func GetConfigDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("getting user config directory: %w", err)
	}
	return filepath.Join(configDir, DefaultConfigDir), nil
}

// getSessionsConfigPath returns the path to the sessions.json file
func getSessionsConfigPath() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, sessionsFileName), nil
}

// LoadSessionsConfig loads the sessions configuration from disk
func LoadSessionsConfig() (*SessionsConfig, error) {
	configPath, err := getSessionsConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty config if file doesn't exist
			return &SessionsConfig{
				Sessions: make(map[string]*SessionInfo),
			}, nil
		}
		return nil, fmt.Errorf("reading sessions config: %w", err)
	}

	var config SessionsConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing sessions config: %w", err)
	}

	if config.Sessions == nil {
		config.Sessions = make(map[string]*SessionInfo)
	}

	return &config, nil
}

// saveSessionsConfig saves the sessions configuration to disk
func saveSessionsConfig(config *SessionsConfig) error {
	configPath, err := getSessionsConfigPath()
	if err != nil {
		return err
	}

	// Ensure directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling sessions config: %w", err)
	}

	// Atomic write
	tempPath := configPath + ".tmp"
	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return fmt.Errorf("writing sessions config: %w", err)
	}

	if err := os.Rename(tempPath, configPath); err != nil {
		os.Remove(tempPath) //nolint:errcheck
		return fmt.Errorf("renaming sessions config: %w", err)
	}

	return nil
}

// generateSessionDir generates a random directory name for a session
func generateSessionDir() (string, error) {
	bytes := make([]byte, sessionDirLength/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// GetOrCreateSession gets an existing session for a server or creates a new one
func GetOrCreateSession(serverURL string) (*SessionInfo, error) {
	config, err := LoadSessionsConfig()
	if err != nil {
		return nil, err
	}

	// Check if session exists for this server
	if session, exists := config.Sessions[serverURL]; exists {
		return session, nil
	}

	// Create new session
	dir, err := generateSessionDir()
	if err != nil {
		return nil, err
	}

	session := &SessionInfo{
		Dir:       dir,
		CreatedAt: time.Now(),
		ServerURL: serverURL,
	}

	config.Sessions[serverURL] = session

	// Set as default if it's the first session
	if config.Default == "" {
		config.Default = serverURL
	}

	if err := saveSessionsConfig(config); err != nil {
		return nil, err
	}

	// Create the session directory
	sessionDir, err := GetSessionDir(serverURL)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		return nil, fmt.Errorf("creating session directory: %w", err)
	}

	return session, nil
}

// GetSessionDir returns the directory path for a server's session
func GetSessionDir(serverURL string) (string, error) {
	config, err := LoadSessionsConfig()
	if err != nil {
		return "", err
	}

	session, exists := config.Sessions[serverURL]
	if !exists {
		return "", fmt.Errorf("no session found for server %s", serverURL)
	}

	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, session.Dir), nil
}

// GetSessionIdentityPath returns the path to the identity file for a server's session
func GetSessionIdentityPath(serverURL string) (string, error) {
	sessionDir, err := GetSessionDir(serverURL)
	if err != nil {
		return "", err
	}
	return filepath.Join(sessionDir, DefaultCredentialsFile), nil
}

// GetDefaultSession returns the default session info, if any
func GetDefaultSession() (*SessionInfo, string, error) {
	config, err := LoadSessionsConfig()
	if err != nil {
		return nil, "", err
	}

	if config.Default == "" {
		return nil, "", fmt.Errorf("no default session configured (run 'deadrop login' first)")
	}

	session, exists := config.Sessions[config.Default]
	if !exists {
		return nil, "", fmt.Errorf("default session %s not found", config.Default)
	}

	return session, config.Default, nil
}

// GetDefaultIdentityPath returns the path to the default session's identity file
func GetDefaultIdentityPath() (string, error) {
	_, serverURL, err := GetDefaultSession()
	if err != nil {
		return "", err
	}
	return GetSessionIdentityPath(serverURL)
}

// SetDefaultSession sets the default session to the specified server
func SetDefaultSession(serverURL string) error {
	config, err := LoadSessionsConfig()
	if err != nil {
		return err
	}

	if _, exists := config.Sessions[serverURL]; !exists {
		return fmt.Errorf("no session found for server %s", serverURL)
	}

	config.Default = serverURL
	return saveSessionsConfig(config)
}

// ListSessions returns all configured sessions
func ListSessions() (map[string]*SessionInfo, string, error) {
	config, err := LoadSessionsConfig()
	if err != nil {
		return nil, "", err
	}
	return config.Sessions, config.Default, nil
}

// SaveIdentity saves the identity token to the session-specific identity file for a server.
// This creates the session if it doesn't exist.
func SaveIdentity(serverURL, token string) error {
	// Get or create session for this server
	_, err := GetOrCreateSession(serverURL)
	if err != nil {
		return fmt.Errorf("getting session: %w", err)
	}

	identityPath, err := GetSessionIdentityPath(serverURL)
	if err != nil {
		return err
	}

	// Ensure the directory exists
	identityDir := filepath.Dir(identityPath)
	if err := os.MkdirAll(identityDir, 0700); err != nil {
		return fmt.Errorf("creating session directory: %w", err)
	}

	// Write token atomically
	tempPath := identityPath + ".tmp"
	if err := os.WriteFile(tempPath, []byte(token+"\n"), 0600); err != nil {
		return fmt.Errorf("writing identity file: %w", err)
	}

	if err := os.Rename(tempPath, identityPath); err != nil {
		os.Remove(tempPath) //nolint:errcheck
		return fmt.Errorf("renaming identity file: %w", err)
	}

	return nil
}

// RenewalThreshold is the time before expiry when a token should be renewed.
// If a token expires within this duration, it will be automatically renewed.
const RenewalThreshold = 10 * time.Minute

// ErrTokenExpired is returned when the token is expired and cannot be renewed.
var ErrTokenExpired = fmt.Errorf("token is expired and cannot be renewed, please log in again")

// LoadIdentity loads the identity token for a specific server.
// Returns the token and its expiry time if valid.
// This function does NOT perform auto-renewal. Use LoadIdentityWithRenewal for that.
func LoadIdentity(serverURL string) (string, time.Time, error) {
	identityPath, err := GetSessionIdentityPath(serverURL)
	if err != nil {
		return "", time.Time{}, err
	}

	data, err := os.ReadFile(identityPath)
	if err != nil {
		return "", time.Time{}, err
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", time.Time{}, fmt.Errorf("identity file is empty")
	}

	// Extract and validate expiry
	exp, err := extractExpiry(token)
	if err != nil {
		return "", time.Time{}, err
	}

	if time.Now().After(exp) {
		return "", time.Time{}, ErrTokenExpired
	}

	return token, exp, nil
}

// LoadIdentityWithRenewal loads the identity token for a specific server,
// automatically renewing it if it's about to expire (within RenewalThreshold).
// Returns the token, expiry time, and whether renewal was performed.
func LoadIdentityWithRenewal(ctx context.Context, serverURL string) (string, time.Time, bool, error) {
	identityPath, err := GetSessionIdentityPath(serverURL)
	if err != nil {
		return "", time.Time{}, false, err
	}

	data, err := os.ReadFile(identityPath)
	if err != nil {
		return "", time.Time{}, false, err
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", time.Time{}, false, fmt.Errorf("identity file is empty")
	}

	// Extract expiry
	exp, err := extractExpiry(token)
	if err != nil {
		return "", time.Time{}, false, err
	}

	now := time.Now()

	// If token is still valid and not near expiry, return it
	if now.Before(exp) && time.Until(exp) > RenewalThreshold {
		return token, exp, false, nil
	}

	// Token is expired or about to expire - try to renew
	newToken, newExp, err := renewToken(ctx, serverURL, token)
	if err != nil {
		// If token is already expired and renewal failed, return error
		if now.After(exp) {
			return "", time.Time{}, false, ErrTokenExpired
		}
		// Token is still valid but renewal failed - return the old token
		// This allows the user to continue working while renewal is retried later
		return token, exp, false, nil
	}

	// Save the renewed token
	if err := SaveIdentity(serverURL, newToken); err != nil {
		// Renewal succeeded but save failed - return the new token anyway
		// (it's valid, just won't be persisted)
		return newToken, newExp, true, nil
	}

	return newToken, newExp, true, nil
}

// renewToken calls the deadrop server to renew a token.
func renewToken(ctx context.Context, serverURL, token string) (string, time.Time, error) {
	client := exchange.NewClient(serverURL)

	resp, err := client.RenewToken(ctx, token)
	if err != nil {
		return "", time.Time{}, err
	}

	// Calculate expiry from response
	exp := time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)

	return resp.AccessToken, exp, nil
}

// LoadDefaultIdentity loads the identity token from the default session.
func LoadDefaultIdentity() (string, time.Time, error) {
	_, serverURL, err := GetDefaultSession()
	if err != nil {
		return "", time.Time{}, err
	}
	return LoadIdentity(serverURL)
}

// DeleteIdentity removes the identity file for a specific server.
func DeleteIdentity(serverURL string) error {
	identityPath, err := GetSessionIdentityPath(serverURL)
	if err != nil {
		return err
	}

	if err := os.Remove(identityPath); err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted
		}
		return fmt.Errorf("deleting identity file: %w", err)
	}

	return nil
}

// DeleteSession removes the entire session for a server, including its directory.
func DeleteSession(serverURL string) error {
	config, err := LoadSessionsConfig()
	if err != nil {
		return err
	}

	session, exists := config.Sessions[serverURL]
	if !exists {
		return nil // No session to delete
	}

	// Get session directory path
	configDir, err := GetConfigDir()
	if err != nil {
		return err
	}
	sessionDir := filepath.Join(configDir, session.Dir)

	// Remove session directory
	if err := os.RemoveAll(sessionDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing session directory: %w", err)
	}

	// Remove from config
	delete(config.Sessions, serverURL)

	// Update default if needed
	if config.Default == serverURL {
		config.Default = ""
		// Set a new default if there are other sessions
		for url := range config.Sessions {
			config.Default = url
			break
		}
	}

	return saveSessionsConfig(config)
}

