// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
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
