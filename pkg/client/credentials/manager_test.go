// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// createTestJWT creates a minimal JWT for testing with the given expiry.
func createTestJWT(exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := map[string]interface{}{
		"exp": exp.Unix(),
		"sub": "test-subject",
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))
	return header + "." + payload + "." + signature
}

func TestNewManager(t *testing.T) {
	validToken := createTestJWT(time.Now().Add(time.Hour))
	expiredToken := createTestJWT(time.Now().Add(-time.Hour))

	tests := []struct {
		name        string
		source      TokenSource
		server      string
		wantErr     bool
		errContains string
	}{
		{
			name:        "valid token and server",
			source:      NewStaticTokenSource(validToken),
			server:      "https://auth.example.com",
			wantErr:     false,
			errContains: "",
		},
		{
			name:        "nil source",
			source:      nil,
			server:      "https://auth.example.com",
			wantErr:     true,
			errContains: "token source is required",
		},
		{
			name:        "empty token",
			source:      NewStaticTokenSource(""),
			server:      "https://auth.example.com",
			wantErr:     true,
			errContains: "static token is empty",
		},
		{
			name:        "empty server",
			source:      NewStaticTokenSource(validToken),
			server:      "",
			wantErr:     true,
			errContains: "server URL is required",
		},
		{
			name:        "expired token",
			source:      NewStaticTokenSource(expiredToken),
			server:      "https://auth.example.com",
			wantErr:     true,
			errContains: "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []Option
			if tt.server != "" {
				opts = append(opts, WithServer(tt.server))
			}
			m, err := NewManager(context.Background(), tt.source, opts...)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewManager() expected error containing %q, got nil", tt.errContains)
				}
				return
			}
			if err != nil {
				t.Errorf("NewManager() unexpected error: %v", err)
				return
			}
			if m == nil {
				t.Error("NewManager() returned nil manager")
			}
			defer m.Close()
		})
	}
}

func TestManagerRegister(t *testing.T) {
	// Create a mock server that returns valid tokens
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"access_token":      createTestJWT(time.Now().Add(time.Hour)),
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
			"expires_in":        3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	centralToken := createTestJWT(time.Now().Add(24 * time.Hour))
	m, err := NewManager(context.Background(), NewStaticTokenSource(centralToken), WithServer(server.URL))
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer m.Close()

	ctx := context.Background()

	// Test successful registration
	err = m.Register(ctx, "test-token", ExchangeSpec{
		Audience: []string{"https://api.example.com"},
	})
	if err != nil {
		t.Errorf("Register() error: %v", err)
	}

	// Test duplicate registration
	err = m.Register(ctx, "test-token", ExchangeSpec{
		Audience: []string{"https://api.example.com"},
	})
	if err == nil {
		t.Error("Register() expected error for duplicate id, got nil")
	}

	// Test empty id
	err = m.Register(ctx, "", ExchangeSpec{
		Audience: []string{"https://api.example.com"},
	})
	if err == nil {
		t.Error("Register() expected error for empty id, got nil")
	}

	// Test empty audience
	err = m.Register(ctx, "another-token", ExchangeSpec{})
	if err == nil {
		t.Error("Register() expected error for empty audience, got nil")
	}
}

func TestManagerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"access_token":      createTestJWT(time.Now().Add(time.Hour)),
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
			"expires_in":        3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	centralToken := createTestJWT(time.Now().Add(24 * time.Hour))
	m, err := NewManager(context.Background(), NewStaticTokenSource(centralToken), WithServer(server.URL))
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer m.Close()

	ctx := context.Background()

	// Register a token
	err = m.Register(ctx, "api-token", ExchangeSpec{
		Audience: []string{"https://api.example.com"},
		Scope:    []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	// Get the token
	token, err := m.Token(ctx, "api-token")
	if err != nil {
		t.Errorf("Token() error: %v", err)
	}
	if token == "" {
		t.Error("Token() returned empty token")
	}

	// Get non-existent token
	_, err = m.Token(ctx, "non-existent")
	if err == nil {
		t.Error("Token() expected error for non-existent id, got nil")
	}
}

func TestManagerTokenSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"access_token":      createTestJWT(time.Now().Add(time.Hour)),
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
			"expires_in":        3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	centralToken := createTestJWT(time.Now().Add(24 * time.Hour))
	m, err := NewManager(context.Background(), NewStaticTokenSource(centralToken), WithServer(server.URL))
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer m.Close()

	ctx := context.Background()

	// Register a token
	err = m.Register(ctx, "api-token", ExchangeSpec{
		Audience: []string{"https://api.example.com"},
	})
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	// Get TokenSource
	ts, err := m.TokenSource("api-token")
	if err != nil {
		t.Fatalf("TokenSource() error: %v", err)
	}

	// Use TokenSource
	token, err := ts.Token(ctx)
	if err != nil {
		t.Errorf("TokenSource.Token() error: %v", err)
	}
	if token == "" {
		t.Error("TokenSource.Token() returned empty token")
	}

	// Get non-existent TokenSource
	_, err = m.TokenSource("non-existent")
	if err == nil {
		t.Error("TokenSource() expected error for non-existent id, got nil")
	}
}

func TestManagerConcurrentAccess(t *testing.T) {
	var requestCount int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()

		resp := map[string]interface{}{
			"access_token":      createTestJWT(time.Now().Add(time.Hour)),
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
			"expires_in":        3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	centralToken := createTestJWT(time.Now().Add(24 * time.Hour))
	m, err := NewManager(context.Background(), NewStaticTokenSource(centralToken), WithServer(server.URL))
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer m.Close()

	ctx := context.Background()

	// Register a token
	err = m.Register(ctx, "api-token", ExchangeSpec{
		Audience: []string{"https://api.example.com"},
	})
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	// Concurrent access
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := m.Token(ctx, "api-token")
			if err != nil {
				t.Errorf("Token() error: %v", err)
			}
			if token == "" {
				t.Error("Token() returned empty token")
			}
		}()
	}
	wg.Wait()

	// Should only have made 1 request (initial registration)
	// since the token is still valid
	mu.Lock()
	count := requestCount
	mu.Unlock()

	if count != 1 {
		t.Errorf("Expected 1 request, got %d", count)
	}
}

func TestExtractExpiry(t *testing.T) {
	futureTime := time.Now().Add(time.Hour).Truncate(time.Second)
	token := createTestJWT(futureTime)

	exp, err := extractExpiry(token)
	if err != nil {
		t.Errorf("extractExpiry() error: %v", err)
	}

	if !exp.Equal(futureTime) {
		t.Errorf("extractExpiry() = %v, want %v", exp, futureTime)
	}

	// Test invalid token
	_, err = extractExpiry("invalid-token")
	if err == nil {
		t.Error("extractExpiry() expected error for invalid token, got nil")
	}
}

func TestOptions(t *testing.T) {
	validToken := createTestJWT(time.Now().Add(time.Hour))

	m, err := NewManager(context.Background(), NewStaticTokenSource(validToken),
		WithServer("https://auth.example.com"),
		WithRefreshBuffer(0.3),
		WithMaxRetries(10),
		WithRetryInterval(2*time.Second),
	)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer m.Close()

	if m.refreshBuffer != 0.3 {
		t.Errorf("refreshBuffer = %v, want 0.3", m.refreshBuffer)
	}
	if m.maxRetries != 10 {
		t.Errorf("maxRetries = %v, want 10", m.maxRetries)
	}
	if m.retryInterval != 2*time.Second {
		t.Errorf("retryInterval = %v, want 2s", m.retryInterval)
	}
}
