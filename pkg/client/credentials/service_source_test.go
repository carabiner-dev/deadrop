// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
)

// createTestJWTWithIat creates a minimal JWT for testing with the given iat and exp.
func createTestJWTWithIat(iat, exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := map[string]any{
		"exp": exp.Unix(),
		"iat": iat.Unix(),
		"sub": "test-subject",
	}
	claimsJSON, _ := json.Marshal(claims) //nolint:errcheck,errchkjson // static test data
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))
	return header + "." + payload + "." + signature
}

// newTestExchangeServer creates an httptest server that responds to /token
// requests with a JWT valid for one hour.
func newTestExchangeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTestTokenResponse(t, w)
	}))
}

func TestNewServiceTokenSource(t *testing.T) {
	identityToken := createTestJWT(time.Now().Add(time.Hour))

	t.Run("valid request and server", func(t *testing.T) {
		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
			testAuthServer,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}
		if source == nil {
			t.Fatal("NewServiceTokenSource() returned nil")
		}
	})

	t.Run("nil request", func(t *testing.T) {
		_, err := NewServiceTokenSource(
			nil,
			testAuthServer,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
		)
		if err == nil {
			t.Error("NewServiceTokenSource() expected error for nil request, got nil")
		}
	})

	t.Run("empty audience", func(t *testing.T) {
		_, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{},
			testAuthServer,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
		)
		if err == nil {
			t.Error("NewServiceTokenSource() expected error for empty audience, got nil")
		}
	})

	t.Run("empty server URL", func(t *testing.T) {
		_, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
			"",
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
		)
		if err == nil {
			t.Error("NewServiceTokenSource() expected error for empty server URL, got nil")
		}
	})
}

func TestServiceTokenSourceOptions(t *testing.T) {
	identityToken := createTestJWT(time.Now().Add(time.Hour))

	t.Run("custom refresh buffer", func(t *testing.T) {
		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
			testAuthServer,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
			WithServiceRefreshBuffer(0.3),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}
		if source.refreshBuffer != 0.3 {
			t.Errorf("refreshBuffer = %v, want 0.3", source.refreshBuffer)
		}
	})

	t.Run("invalid refresh buffer ignored", func(t *testing.T) {
		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
			testAuthServer,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
			WithServiceRefreshBuffer(0.0),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}
		if source.refreshBuffer != 0.2 {
			t.Errorf("refreshBuffer = %v, want 0.2 (default)", source.refreshBuffer)
		}
	})

	t.Run("persistence enabled", func(t *testing.T) {
		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
			testAuthServer,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
			WithServicePersistence(),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}
		if !source.persist {
			t.Error("persist = false, want true")
		}
	})

	t.Run("nil identity source ignored", func(t *testing.T) {
		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
			testAuthServer,
			WithServiceIdentitySource(nil),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}
		// Should have fallen back to default source
		if source.source == nil {
			t.Error("source is nil, expected default source")
		}
	})
}

func TestServiceTokenSourceToken(t *testing.T) {
	identityToken := createTestJWT(time.Now().Add(24 * time.Hour))
	server := newTestExchangeServer(t)
	defer server.Close()

	ctx := context.Background()

	t.Run("first call exchanges token", func(t *testing.T) {
		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
			server.URL,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}

		token, err := source.Token(ctx)
		if err != nil {
			t.Fatalf("Token() error: %v", err)
		}
		if token == "" {
			t.Error("Token() returned empty token")
		}
		// Token should be different from identity (it's exchanged)
		if token == identityToken {
			t.Error("Token() returned identity token, expected exchanged token")
		}
	})

	t.Run("subsequent calls return cached token", func(t *testing.T) {
		var requestCount int
		var mu sync.Mutex

		countServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requestCount++
			mu.Unlock()

			writeTestTokenResponse(t, w)
		}))
		defer countServer.Close()

		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
			countServer.URL,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}

		// First call - should exchange
		token1, err := source.Token(ctx)
		if err != nil {
			t.Fatalf("Token() first call error: %v", err)
		}

		// Subsequent calls - should return cached
		for i := range 10 {
			token, err := source.Token(ctx)
			if err != nil {
				t.Fatalf("Token() call %d error: %v", i+2, err)
			}
			if token != token1 {
				t.Errorf("Token() call %d returned different token", i+2)
			}
		}

		mu.Lock()
		count := requestCount
		mu.Unlock()

		if count != 1 {
			t.Errorf("Expected 1 exchange request, got %d", count)
		}
	})

	t.Run("exchange with scope and resource", func(t *testing.T) {
		var receivedScope string
		var receivedResource []string

		specServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm() //nolint:errcheck,gosec
			receivedScope = r.FormValue("scope")
			receivedResource = r.Form["resource"]

			writeTestTokenResponse(t, w)
		}))
		defer specServer.Close()

		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{
				Audience: []string{testAPIAudience},
				Scope:    []string{"read", "write"},
				Resource: []string{"res1", "res2"},
			},
			specServer.URL,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}

		_, err = source.Token(ctx)
		if err != nil {
			t.Fatalf("Token() error: %v", err)
		}

		if receivedScope != "read write" {
			t.Errorf("scope = %q, want %q", receivedScope, "read write")
		}
		if len(receivedResource) != 2 || receivedResource[0] != "res1" || receivedResource[1] != "res2" {
			t.Errorf("resource = %v, want [res1 res2]", receivedResource)
		}
	})

	t.Run("exchange failure returns error", func(t *testing.T) {
		failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck,gosec
				"error":             "server_error",
				"error_description": "internal failure",
			})
		}))
		defer failServer.Close()

		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
			failServer.URL,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}

		_, err = source.Token(ctx)
		if err == nil {
			t.Error("Token() expected error for failed exchange, got nil")
		}
	})

	t.Run("identity source failure returns error", func(t *testing.T) {
		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
			server.URL,
			WithServiceIdentitySource(NewStaticTokenSource("")),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}

		_, err = source.Token(ctx)
		if err == nil {
			t.Error("Token() expected error for failed identity source, got nil")
		}
	})
}

func TestServiceTokenSourceRefresh(t *testing.T) {
	identityToken := createTestJWT(time.Now().Add(24 * time.Hour))
	ctx := context.Background()

	t.Run("triggers background refresh when approaching expiry", func(t *testing.T) {
		var requestCount int
		var mu sync.Mutex

		refreshServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requestCount++
			mu.Unlock()

			writeTestTokenResponse(t, w)
		}))
		defer refreshServer.Close()

		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
			refreshServer.URL,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}

		// First call - gets a token
		_, err = source.Token(ctx)
		if err != nil {
			t.Fatalf("Token() error: %v", err)
		}

		// Simulate a token that's about to expire (5% of lifetime remaining)
		source.mu.Lock()
		now := time.Now()
		source.issuedAt = now.Add(-57 * time.Minute) // 57 min ago
		source.expiresAt = now.Add(3 * time.Minute)  // 3 min left out of 60
		source.mu.Unlock()

		// This call should trigger a background refresh
		token, err := source.Token(ctx)
		if err != nil {
			t.Fatalf("Token() error: %v", err)
		}
		if token == "" {
			t.Error("Token() returned empty token")
		}

		// Wait for background refresh to complete
		time.Sleep(200 * time.Millisecond)

		mu.Lock()
		count := requestCount
		mu.Unlock()

		// Should have 2 requests: initial exchange + background refresh
		if count != 2 {
			t.Errorf("Expected 2 exchange requests, got %d", count)
		}
	})

	t.Run("does not refresh when token is fresh", func(t *testing.T) {
		var requestCount int
		var mu sync.Mutex

		noRefreshServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requestCount++
			mu.Unlock()

			writeTestTokenResponse(t, w)
		}))
		defer noRefreshServer.Close()

		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
			noRefreshServer.URL,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}

		// First call
		_, err = source.Token(ctx)
		if err != nil {
			t.Fatalf("Token() error: %v", err)
		}

		// Multiple calls with a fresh token
		for range 10 {
			_, err = source.Token(ctx)
			if err != nil {
				t.Fatalf("Token() error: %v", err)
			}
		}

		time.Sleep(100 * time.Millisecond)

		mu.Lock()
		count := requestCount
		mu.Unlock()

		if count != 1 {
			t.Errorf("Expected 1 exchange request (no refresh), got %d", count)
		}
	})
}

func TestServiceTokenSourceConcurrent(t *testing.T) {
	identityToken := createTestJWT(time.Now().Add(24 * time.Hour))
	server := newTestExchangeServer(t)
	defer server.Close()

	source, err := NewServiceTokenSource(
		&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
		server.URL,
		WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
	)
	if err != nil {
		t.Fatalf("NewServiceTokenSource() error: %v", err)
	}

	ctx := context.Background()

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := source.Token(ctx)
			if err != nil {
				t.Errorf("Token() error: %v", err)
			}
			if token == "" {
				t.Error("Token() returned empty token")
			}
		}()
	}
	wg.Wait()
}

func TestServiceTokenSourcePersistence(t *testing.T) {
	identityToken := createTestJWT(time.Now().Add(24 * time.Hour))
	ctx := context.Background()

	// Set up a temp config dir so we don't affect the real one
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	serverURL := "https://persist-test.example.com"

	// Create a session so SaveExchangedToken/LoadExchangedToken work
	_, err := GetOrCreateSession(serverURL)
	if err != nil {
		t.Fatalf("GetOrCreateSession() error: %v", err)
	}

	t.Run("saves token to disk when persistence enabled", func(t *testing.T) {
		server := newTestExchangeServer(t)
		defer server.Close()

		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{"https://api.persist.com"}},
			server.URL,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
			WithServicePersistence(),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}
		// Override serverURL for persistence to use our test session
		source.serverURL = serverURL

		token, err := source.Token(ctx)
		if err != nil {
			t.Fatalf("Token() error: %v", err)
		}

		// Verify the token was persisted
		loaded, _, loadErr := LoadExchangedToken(serverURL, &exchange.ExchangeRequest{Audience: []string{"https://api.persist.com"}})
		if loadErr != nil {
			t.Fatalf("LoadExchangedToken() error: %v", loadErr)
		}
		if loaded != token {
			t.Error("Persisted token does not match returned token")
		}
	})

	t.Run("loads persisted token on new source", func(t *testing.T) {
		req := &exchange.ExchangeRequest{Audience: []string{"https://api.load-test.com"}}

		// Pre-persist a token
		now := time.Now()
		persistedToken := createTestJWTWithIat(now, now.Add(time.Hour))
		err := SaveExchangedToken(serverURL, req, persistedToken, now.Add(time.Hour))
		if err != nil {
			t.Fatalf("SaveExchangedToken() error: %v", err)
		}

		// Create a source that would fail on exchange (to prove it loads from cache)
		failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer failServer.Close()

		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{"https://api.load-test.com"}},
			failServer.URL,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
			WithServicePersistence(),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}
		source.serverURL = serverURL

		token, err := source.Token(ctx)
		if err != nil {
			t.Fatalf("Token() error: %v", err)
		}
		if token != persistedToken {
			t.Error("Token() did not return persisted token")
		}
	})

	t.Run("does not persist without option", func(t *testing.T) {
		req := &exchange.ExchangeRequest{Audience: []string{"https://api.no-persist.com"}}

		server := newTestExchangeServer(t)
		defer server.Close()

		source, err := NewServiceTokenSource(
			&exchange.ExchangeRequest{Audience: []string{"https://api.no-persist.com"}},
			server.URL,
			WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
		)
		if err != nil {
			t.Fatalf("NewServiceTokenSource() error: %v", err)
		}
		source.serverURL = serverURL

		_, err = source.Token(ctx)
		if err != nil {
			t.Fatalf("Token() error: %v", err)
		}

		// Verify no token was persisted
		tokensDir, _ := GetTokensDir(serverURL) //nolint:errcheck // missing dir means no token persisted
		hash := HashExchangeRequest(req)
		tokenPath := filepath.Join(tokensDir, hash+".json")
		if _, err := os.Stat(tokenPath); err == nil {
			t.Error("Token was persisted to disk without WithServicePersistence()")
		}
	})
}

func TestServiceTokenSourceContextCancellation(t *testing.T) {
	identityToken := createTestJWT(time.Now().Add(24 * time.Hour))

	// Slow server to allow context cancellation
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer slowServer.Close()

	source, err := NewServiceTokenSource(
		&exchange.ExchangeRequest{Audience: []string{testAPIAudience}},
		slowServer.URL,
		WithServiceIdentitySource(NewStaticTokenSource(identityToken)),
	)
	if err != nil {
		t.Fatalf("NewServiceTokenSource() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = source.Token(ctx)
	if err == nil {
		t.Error("Token() expected error for cancelled context, got nil")
	}
}

func TestShouldRefresh(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		issuedAt time.Time
		exp      time.Time
		buffer   float64
		want     bool
	}{
		{
			name:     "fresh token (50% remaining)",
			issuedAt: now.Add(-30 * time.Minute),
			exp:      now.Add(30 * time.Minute),
			buffer:   0.2,
			want:     false,
		},
		{
			name:     "token at 85% used (15% remaining)",
			issuedAt: now.Add(-51 * time.Minute),
			exp:      now.Add(9 * time.Minute),
			buffer:   0.2,
			want:     true,
		},
		{
			name:     "token at exactly 20% remaining",
			issuedAt: now.Add(-48 * time.Minute),
			exp:      now.Add(12 * time.Minute),
			buffer:   0.2,
			want:     false,
		},
		{
			name:     "expired token",
			issuedAt: now.Add(-2 * time.Hour),
			exp:      now.Add(-1 * time.Minute),
			buffer:   0.2,
			want:     true,
		},
		{
			name:     "zero lifetime",
			issuedAt: now,
			exp:      now,
			buffer:   0.2,
			want:     true,
		},
		{
			name:     "custom buffer 0.5 - needs refresh at 40% remaining",
			issuedAt: now.Add(-60 * time.Minute),
			exp:      now.Add(40 * time.Minute),
			buffer:   0.5,
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldRefresh(now, tt.issuedAt, tt.exp, tt.buffer)
			if got != tt.want {
				remaining := tt.exp.Sub(now)
				total := tt.exp.Sub(tt.issuedAt)
				t.Errorf("shouldRefresh() = %v, want %v (remaining=%v, total=%v, ratio=%.2f)",
					got, tt.want, remaining, total, float64(remaining)/float64(total))
			}
		})
	}
}

func TestExtractTokenIssuedAt(t *testing.T) {
	t.Run("token with iat claim", func(t *testing.T) {
		iat := time.Now().Add(-30 * time.Minute).Truncate(time.Second)
		exp := time.Now().Add(30 * time.Minute).Truncate(time.Second)
		token := createTestJWTWithIat(iat, exp)

		got := extractTokenIssuedAt(token, exp)
		if !got.Equal(iat) {
			t.Errorf("extractTokenIssuedAt() = %v, want %v", got, iat)
		}
	})

	t.Run("token without iat claim", func(t *testing.T) {
		exp := time.Now().Add(30 * time.Minute)
		token := createTestJWT(exp) // createTestJWT doesn't include iat

		got := extractTokenIssuedAt(token, exp)
		if !got.Equal(exp) {
			t.Errorf("extractTokenIssuedAt() = %v, want %v (should fallback to expiresAt)", got, exp)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		exp := time.Now().Add(30 * time.Minute)
		got := extractTokenIssuedAt("not-a-jwt", exp)
		if !got.Equal(exp) {
			t.Errorf("extractTokenIssuedAt() = %v, want %v (should fallback to expiresAt)", got, exp)
		}
	})
}

func TestServiceTokenSourceImplementsInterface(t *testing.T) {
	// Compile-time check that ServiceTokenSource implements TokenSource
	var _ TokenSource = (*ServiceTokenSource)(nil)
}
