// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// DefaultCredentialsEnvVar is the environment variable checked for credentials.
	DefaultCredentialsEnvVar = "CARABINER_CREDENTIALS"

	// DefaultCredentialsFile is the filename for the default credentials file.
	DefaultCredentialsFile = "identity.json"

	// DefaultConfigDir is the subdirectory under os.UserConfigDir for carabiner config.
	DefaultConfigDir = "carabiner"
)

// StaticTokenSource returns a fixed token. Useful for testing.
type StaticTokenSource struct {
	token string
}

// NewStaticTokenSource creates a TokenSource that always returns the same token.
func NewStaticTokenSource(token string) *StaticTokenSource {
	return &StaticTokenSource{token: token}
}

func (s *StaticTokenSource) Token(_ context.Context) (string, error) {
	if s.token == "" {
		return "", errors.New("static token is empty")
	}
	return s.token, nil
}

// FileTokenSource reads a token from a file. The file is read on each call
// to Token(), allowing for external token rotation.
type FileTokenSource struct {
	path string
	mu   sync.RWMutex
}

// NewFileTokenSource creates a TokenSource that reads from a file.
// The file should contain a JWT token (whitespace is trimmed).
func NewFileTokenSource(path string) *FileTokenSource {
	return &FileTokenSource{path: path}
}

func (f *FileTokenSource) Token(_ context.Context) (string, error) {
	f.mu.RLock()
	path := f.path
	f.mu.RUnlock()

	if path == "" {
		return "", errors.New("file path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading token file: %w", err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("token file is empty")
	}

	return token, nil
}

// EnvTokenSource reads a token from an environment variable.
type EnvTokenSource struct {
	envVar string
}

// NewEnvTokenSource creates a TokenSource that reads from an environment variable.
func NewEnvTokenSource(envVar string) *EnvTokenSource {
	return &EnvTokenSource{envVar: envVar}
}

func (e *EnvTokenSource) Token(_ context.Context) (string, error) {
	if e.envVar == "" {
		return "", errors.New("environment variable name is empty")
	}

	token := os.Getenv(e.envVar)
	if token == "" {
		return "", fmt.Errorf("environment variable %q is not set or empty", e.envVar)
	}

	return strings.TrimSpace(token), nil
}

// ChainedTokenSource tries multiple TokenSources in order until one succeeds.
type ChainedTokenSource struct {
	sources []TokenSource
}

// NewChainedTokenSource creates a TokenSource that tries each source in order.
// The first source that returns a valid token is used.
func NewChainedTokenSource(sources ...TokenSource) *ChainedTokenSource {
	return &ChainedTokenSource{sources: sources}
}

func (c *ChainedTokenSource) Token(ctx context.Context) (string, error) {
	if len(c.sources) == 0 {
		return "", errors.New("no token sources configured")
	}

	var errs []error
	for _, source := range c.sources {
		token, err := source.Token(ctx)
		if err == nil && token != "" {
			return token, nil
		}
		if err != nil {
			errs = append(errs, err)
		}
	}

	return "", fmt.Errorf("all token sources failed: %v", errs)
}

// DefaultEnvTokenSource returns a TokenSource that reads from the
// CARABINER_CREDENTIALS environment variable.
func DefaultEnvTokenSource() *EnvTokenSource {
	return NewEnvTokenSource(DefaultCredentialsEnvVar)
}

// DefaultFileTokenSource returns a TokenSource that reads from the default
// credentials file at os.UserConfigDir()/carabiner/identity.json.
func DefaultFileTokenSource() (*FileTokenSource, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("getting user config directory: %w", err)
	}
	path := filepath.Join(configDir, DefaultConfigDir, DefaultCredentialsFile)
	return NewFileTokenSource(path), nil
}

// DefaultTokenSource returns a ChainedTokenSource that tries:
// 1. CARABINER_CREDENTIALS environment variable
// 2. os.UserConfigDir()/carabiner/identity.json
func DefaultTokenSource() (TokenSource, error) {
	fileSource, err := DefaultFileTokenSource()
	if err != nil {
		return nil, err
	}
	return NewChainedTokenSource(
		DefaultEnvTokenSource(),
		fileSource,
	), nil
}
