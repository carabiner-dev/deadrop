// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/carabiner-dev/deadrop/pkg/client/credentials"
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

// getConfigDir returns the carabiner config directory path
func getConfigDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("getting user config directory: %w", err)
	}
	return filepath.Join(configDir, credentials.DefaultConfigDir), nil
}

// getSessionsConfigPath returns the path to the sessions.json file
func getSessionsConfigPath() (string, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, sessionsFileName), nil
}

// loadSessionsConfig loads the sessions configuration from disk
func loadSessionsConfig() (*SessionsConfig, error) {
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

// getOrCreateSession gets an existing session for a server or creates a new one
func getOrCreateSession(serverURL string) (*SessionInfo, error) {
	config, err := loadSessionsConfig()
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
	sessionDir, err := getSessionDir(serverURL)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		return nil, fmt.Errorf("creating session directory: %w", err)
	}

	return session, nil
}

// getSessionDir returns the directory path for a server's session
func getSessionDir(serverURL string) (string, error) {
	config, err := loadSessionsConfig()
	if err != nil {
		return "", err
	}

	session, exists := config.Sessions[serverURL]
	if !exists {
		return "", fmt.Errorf("no session found for server %s", serverURL)
	}

	configDir, err := getConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, session.Dir), nil
}

// getSessionIdentityPath returns the path to the identity file for a server's session
func getSessionIdentityPath(serverURL string) (string, error) {
	sessionDir, err := getSessionDir(serverURL)
	if err != nil {
		return "", err
	}
	return filepath.Join(sessionDir, credentials.DefaultCredentialsFile), nil
}

// getDefaultSession returns the default session info, if any
func getDefaultSession() (*SessionInfo, string, error) {
	config, err := loadSessionsConfig()
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

// getDefaultIdentityPath returns the path to the default session's identity file
func getDefaultIdentityPath() (string, error) {
	_, serverURL, err := getDefaultSession()
	if err != nil {
		return "", err
	}
	return getSessionIdentityPath(serverURL)
}

// setDefaultSession sets the default session to the specified server
func setDefaultSession(serverURL string) error {
	config, err := loadSessionsConfig()
	if err != nil {
		return err
	}

	if _, exists := config.Sessions[serverURL]; !exists {
		return fmt.Errorf("no session found for server %s", serverURL)
	}

	config.Default = serverURL
	return saveSessionsConfig(config)
}

// listSessions returns all configured sessions
func listSessions() (map[string]*SessionInfo, string, error) {
	config, err := loadSessionsConfig()
	if err != nil {
		return nil, "", err
	}
	return config.Sessions, config.Default, nil
}
