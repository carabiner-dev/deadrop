// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/adrg/xdg"
)

const (
	tokenFileName = "tokens.json"
	dirPerm       = 0700 // User-only directory permissions
	filePerm      = 0600 // User-only file permissions
)

// TokenStorage manages persistent token storage
type TokenStorage struct {
	DataDir   string // XDG_DATA_HOME/deadrop
	ConfigDir string // XDG_CONFIG_HOME/deadrop
}

// StoredToken represents cached token with metadata
type StoredToken struct {
	Token         string    `json:"token"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Provider      string    `json:"provider"` // "google", "microsoft"
	ServerURL     string    `json:"server_url"`
	OriginalToken string    `json:"original_token,omitempty"` // Optional: cache OAuth token
}

// NewTokenStorage creates storage with XDG paths
func NewTokenStorage() (*TokenStorage, error) {
	dataDir := filepath.Join(xdg.DataHome, "deadrop")
	configDir := filepath.Join(xdg.ConfigHome, "deadrop")

	// Create directories if they don't exist
	if err := os.MkdirAll(dataDir, dirPerm); err != nil {
		return nil, fmt.Errorf("creating data directory: %w", err)
	}
	if err := os.MkdirAll(configDir, dirPerm); err != nil {
		return nil, fmt.Errorf("creating config directory: %w", err)
	}

	return &TokenStorage{
		DataDir:   dataDir,
		ConfigDir: configDir,
	}, nil
}

// SaveToken stores token to disk with atomic write
func (s *TokenStorage) SaveToken(ctx context.Context, token *StoredToken) error {
	tokenPath := filepath.Join(s.DataDir, tokenFileName)

	// Marshal token to JSON
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling token: %w", err)
	}

	// Atomic write: write to temp file, then rename
	tempPath := tokenPath + ".tmp"
	if err := os.WriteFile(tempPath, data, filePerm); err != nil {
		return fmt.Errorf("writing token file: %w", err)
	}

	if err := os.Rename(tempPath, tokenPath); err != nil {
		os.Remove(tempPath) //nolint:errcheck // Clean up temp file on error
		return fmt.Errorf("renaming token file: %w", err)
	}

	return nil
}

// LoadToken retrieves token from disk
func (s *TokenStorage) LoadToken(ctx context.Context) (*StoredToken, error) {
	tokenPath := filepath.Join(s.DataDir, tokenFileName)

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no cached token found")
		}
		return nil, fmt.Errorf("reading token file: %w", err)
	}

	var token StoredToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("parsing token file: %w", err)
	}

	return &token, nil
}

// DeleteToken removes cached token
func (s *TokenStorage) DeleteToken(ctx context.Context) error {
	tokenPath := filepath.Join(s.DataDir, tokenFileName)

	if err := os.Remove(tokenPath); err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted
		}
		return fmt.Errorf("deleting token file: %w", err)
	}

	return nil
}

// IsValid checks if token is still valid (not expired)
func (t *StoredToken) IsValid() bool {
	return time.Now().Before(t.ExpiresAt)
}

// TimeUntilExpiry returns the duration until the token expires
func (t *StoredToken) TimeUntilExpiry() time.Duration {
	return time.Until(t.ExpiresAt)
}
