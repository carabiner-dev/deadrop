// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
)

// Common URLs used across the package tests.
const (
	testAPIAudience = "https://api.example.com"
	testAuthServer  = "https://auth.example.com"
)

// createTestJWT creates a minimal JWT for testing with the given expiry.
func createTestJWT(exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := map[string]interface{}{
		"exp": exp.Unix(),
		"sub": "test-subject",
	}
	claimsJSON, _ := json.Marshal(claims) //nolint:errcheck,errchkjson // static test data
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))
	return header + "." + payload + "." + signature
}

// writeTestTokenResponse writes a standard token exchange response with a
// token valid for one hour.
func writeTestTokenResponse(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	now := time.Now()
	lifetime := time.Hour
	resp := map[string]interface{}{ //nolint:gosec // test token, not a credential
		"access_token":      createTestJWTWithIat(now, now.Add(lifetime)),
		"token_type":        "Bearer",
		"issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"expires_in":        int64(lifetime.Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		t.Errorf("encoding token response: %v", err)
	}
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
			server:      testAuthServer,
			wantErr:     false,
			errContains: "",
		},
		{
			name:        "empty token",
			source:      NewStaticTokenSource(""),
			server:      testAuthServer,
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
			server:      testAuthServer,
			wantErr:     true,
			errContains: "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []Option
			if tt.source != nil {
				opts = append(opts, WithTokenSource(tt.source))
			}
			if tt.server != "" {
				opts = append(opts, WithServer(tt.server))
			}
			m, err := NewManager(context.Background(), opts...)
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
			defer m.Close() //nolint:errcheck
		})
	}
}

func TestManagerRegister(t *testing.T) {
	// Create a mock server that returns valid tokens
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTestTokenResponse(t, w)
	}))
	defer server.Close()

	centralToken := createTestJWT(time.Now().Add(24 * time.Hour))
	m, err := NewManager(context.Background(), WithTokenSource(NewStaticTokenSource(centralToken)), WithServer(server.URL))
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer m.Close() //nolint:errcheck

	ctx := context.Background()

	// Test successful registration
	err = m.Register(ctx, "test-token", &exchange.ExchangeRequest{
		Audience: []string{testAPIAudience},
	})
	if err != nil {
		t.Errorf("Register() error: %v", err)
	}

	// Test duplicate registration
	err = m.Register(ctx, "test-token", &exchange.ExchangeRequest{
		Audience: []string{testAPIAudience},
	})
	if err == nil {
		t.Error("Register() expected error for duplicate id, got nil")
	}

	// Test empty id
	err = m.Register(ctx, "", &exchange.ExchangeRequest{
		Audience: []string{testAPIAudience},
	})
	if err == nil {
		t.Error("Register() expected error for empty id, got nil")
	}

	// Test empty audience
	err = m.Register(ctx, "another-token", &exchange.ExchangeRequest{})
	if err == nil {
		t.Error("Register() expected error for empty audience, got nil")
	}
}

func TestManagerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTestTokenResponse(t, w)
	}))
	defer server.Close()

	centralToken := createTestJWT(time.Now().Add(24 * time.Hour))
	m, err := NewManager(context.Background(), WithTokenSource(NewStaticTokenSource(centralToken)), WithServer(server.URL))
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer m.Close() //nolint:errcheck

	ctx := context.Background()

	// Register a token
	err = m.Register(ctx, "api-token", &exchange.ExchangeRequest{
		Audience: []string{testAPIAudience},
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
		writeTestTokenResponse(t, w)
	}))
	defer server.Close()

	centralToken := createTestJWT(time.Now().Add(24 * time.Hour))
	m, err := NewManager(context.Background(), WithTokenSource(NewStaticTokenSource(centralToken)), WithServer(server.URL))
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer m.Close() //nolint:errcheck

	ctx := context.Background()

	// Register a token
	err = m.Register(ctx, "api-token", &exchange.ExchangeRequest{
		Audience: []string{testAPIAudience},
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

		writeTestTokenResponse(t, w)
	}))
	defer server.Close()

	centralToken := createTestJWT(time.Now().Add(24 * time.Hour))
	m, err := NewManager(context.Background(), WithTokenSource(NewStaticTokenSource(centralToken)), WithServer(server.URL))
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer m.Close() //nolint:errcheck

	ctx := context.Background()

	// Register a token
	err = m.Register(ctx, "api-token", &exchange.ExchangeRequest{
		Audience: []string{testAPIAudience},
	})
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	// Concurrent access
	var wg sync.WaitGroup
	for range 100 {
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

	m, err := NewManager(context.Background(),
		WithTokenSource(NewStaticTokenSource(validToken)),
		WithServer(testAuthServer),
		WithRefreshBuffer(0.3),
		WithMaxRetries(10),
		WithRetryInterval(2*time.Second),
	)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer m.Close() //nolint:errcheck

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

// countingTokenSource wraps a TokenSource and counts how many times Token() is called.
type countingTokenSource struct {
	source TokenSource
	count  int
	mu     sync.Mutex
}

func (c *countingTokenSource) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	c.count++
	c.mu.Unlock()
	return c.source.Token(ctx)
}

func (c *countingTokenSource) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

func TestCentralTokenCaching(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTestTokenResponse(t, w)
	}))
	defer server.Close()

	// Create a counting source to track how many times the central token is read
	centralToken := createTestJWT(time.Now().Add(24 * time.Hour))
	countingSource := &countingTokenSource{
		source: NewStaticTokenSource(centralToken),
	}

	m, err := NewManager(context.Background(), WithTokenSource(countingSource), WithServer(server.URL))
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer m.Close() //nolint:errcheck

	// Initial read happens during NewManager
	if count := countingSource.Count(); count != 1 {
		t.Errorf("Expected 1 source read after NewManager, got %d", count)
	}

	ctx := context.Background()

	// Register multiple tokens
	for i := range 3 {
		err = m.Register(ctx, fmt.Sprintf("token-%d", i), &exchange.ExchangeRequest{
			Audience: []string{testAPIAudience},
		})
		if err != nil {
			t.Fatalf("Register() error: %v", err)
		}
	}

	// Central token should still only be read once (it's cached)
	if count := countingSource.Count(); count != 1 {
		t.Errorf("Expected 1 source read after registrations, got %d", count)
	}

	// Access tokens multiple times
	for range 10 {
		for j := range 3 {
			_, err := m.Token(ctx, fmt.Sprintf("token-%d", j))
			if err != nil {
				t.Errorf("Token() error: %v", err)
			}
		}
	}

	// Central token should still only be read once (cached, not expired)
	if count := countingSource.Count(); count != 1 {
		t.Errorf("Expected 1 source read after token accesses, got %d", count)
	}
}
