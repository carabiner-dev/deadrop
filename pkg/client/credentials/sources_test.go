// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestStaticTokenSource(t *testing.T) {
	ctx := context.Background()

	t.Run("valid token", func(t *testing.T) {
		source := NewStaticTokenSource("my-token")
		token, err := source.Token(ctx)
		if err != nil {
			t.Errorf("Token() error: %v", err)
		}
		if token != "my-token" {
			t.Errorf("Token() = %q, want %q", token, "my-token")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		source := NewStaticTokenSource("")
		_, err := source.Token(ctx)
		if err == nil {
			t.Error("Token() expected error for empty token, got nil")
		}
	})
}

func TestFileTokenSource(t *testing.T) {
	ctx := context.Background()

	t.Run("valid file", func(t *testing.T) {
		// Create temp file with token
		tmpDir := t.TempDir()
		tokenFile := filepath.Join(tmpDir, "token")
		if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0600); err != nil {
			t.Fatalf("WriteFile() error: %v", err)
		}

		source := NewFileTokenSource(tokenFile)
		token, err := source.Token(ctx)
		if err != nil {
			t.Errorf("Token() error: %v", err)
		}
		if token != "file-token" {
			t.Errorf("Token() = %q, want %q", token, "file-token")
		}
	})

	t.Run("file with whitespace", func(t *testing.T) {
		tmpDir := t.TempDir()
		tokenFile := filepath.Join(tmpDir, "token")
		if err := os.WriteFile(tokenFile, []byte("  token-with-spaces  \n\n"), 0600); err != nil {
			t.Fatalf("WriteFile() error: %v", err)
		}

		source := NewFileTokenSource(tokenFile)
		token, err := source.Token(ctx)
		if err != nil {
			t.Errorf("Token() error: %v", err)
		}
		if token != "token-with-spaces" {
			t.Errorf("Token() = %q, want %q", token, "token-with-spaces")
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		source := NewFileTokenSource("/non/existent/path")
		_, err := source.Token(ctx)
		if err == nil {
			t.Error("Token() expected error for non-existent file, got nil")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		tmpDir := t.TempDir()
		tokenFile := filepath.Join(tmpDir, "token")
		if err := os.WriteFile(tokenFile, []byte(""), 0600); err != nil {
			t.Fatalf("WriteFile() error: %v", err)
		}

		source := NewFileTokenSource(tokenFile)
		_, err := source.Token(ctx)
		if err == nil {
			t.Error("Token() expected error for empty file, got nil")
		}
	})

	t.Run("empty path", func(t *testing.T) {
		source := NewFileTokenSource("")
		_, err := source.Token(ctx)
		if err == nil {
			t.Error("Token() expected error for empty path, got nil")
		}
	})

	t.Run("token rotation", func(t *testing.T) {
		tmpDir := t.TempDir()
		tokenFile := filepath.Join(tmpDir, "token")
		if err := os.WriteFile(tokenFile, []byte("token-v1"), 0600); err != nil {
			t.Fatalf("WriteFile() error: %v", err)
		}

		source := NewFileTokenSource(tokenFile)

		// First read
		token, err := source.Token(ctx)
		if err != nil {
			t.Errorf("Token() error: %v", err)
		}
		if token != "token-v1" {
			t.Errorf("Token() = %q, want %q", token, "token-v1")
		}

		// Update file
		if err := os.WriteFile(tokenFile, []byte("token-v2"), 0600); err != nil {
			t.Fatalf("WriteFile() error: %v", err)
		}

		// Second read should get new token
		token, err = source.Token(ctx)
		if err != nil {
			t.Errorf("Token() error: %v", err)
		}
		if token != "token-v2" {
			t.Errorf("Token() = %q, want %q", token, "token-v2")
		}
	})
}

func TestEnvTokenSource(t *testing.T) {
	ctx := context.Background()

	t.Run("valid env var", func(t *testing.T) {
		t.Setenv("TEST_TOKEN", "env-token")

		source := NewEnvTokenSource("TEST_TOKEN")
		token, err := source.Token(ctx)
		if err != nil {
			t.Errorf("Token() error: %v", err)
		}
		if token != "env-token" {
			t.Errorf("Token() = %q, want %q", token, "env-token")
		}
	})

	t.Run("env var with whitespace", func(t *testing.T) {
		t.Setenv("TEST_TOKEN_WS", "  token-with-spaces  ")

		source := NewEnvTokenSource("TEST_TOKEN_WS")
		token, err := source.Token(ctx)
		if err != nil {
			t.Errorf("Token() error: %v", err)
		}
		if token != "token-with-spaces" {
			t.Errorf("Token() = %q, want %q", token, "token-with-spaces")
		}
	})

	t.Run("unset env var", func(t *testing.T) {
		source := NewEnvTokenSource("DEFINITELY_NOT_SET_VAR_12345")
		_, err := source.Token(ctx)
		if err == nil {
			t.Error("Token() expected error for unset env var, got nil")
		}
	})

	t.Run("empty env var name", func(t *testing.T) {
		source := NewEnvTokenSource("")
		_, err := source.Token(ctx)
		if err == nil {
			t.Error("Token() expected error for empty env var name, got nil")
		}
	})
}
