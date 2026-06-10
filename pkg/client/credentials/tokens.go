// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
)

// cleanupProbability is the chance (1 in N) of running cleanup on each token load.
// Set to 10 means ~10% chance of cleanup on each LoadExchangedTokenWithRenewal call.
const cleanupProbability = 10

const (
	tokensDirName = "tokens"
)

// CachedToken represents an exchanged token stored on disk.
type CachedToken struct {
	Token     string                    `json:"token"`
	ExpiresAt time.Time                 `json:"expires_at"`
	Spec      *exchange.ExchangeRequest `json:"spec"`
}

// HashExchangeRequest generates a deterministic hash for an exchange request.
// This is used to create unique filenames for cached tokens. Only the Audience,
// Scope, and Resource fields are hashed.
func HashExchangeRequest(req *exchange.ExchangeRequest) string {
	// Sort all arrays for deterministic ordering
	audience := make([]string, len(req.Audience))
	copy(audience, req.Audience)
	sort.Strings(audience)

	scope := make([]string, len(req.Scope))
	copy(scope, req.Scope)
	sort.Strings(scope)

	resource := make([]string, len(req.Resource))
	copy(resource, req.Resource)
	sort.Strings(resource)

	// Build a canonical string representation
	parts := []string{
		"aud:" + strings.Join(audience, ","),
		"scope:" + strings.Join(scope, ","),
		"res:" + strings.Join(resource, ","),
	}
	canonical := strings.Join(parts, "|")

	// Hash it
	hash := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(hash[:])
}

// GetTokensDir returns the tokens directory path for a server's session.
func GetTokensDir(serverURL string) (string, error) {
	sessionDir, err := GetSessionDir(serverURL)
	if err != nil {
		return "", err
	}
	return filepath.Join(sessionDir, tokensDirName), nil
}

// getTokenFilePath returns the path to a specific token file.
func getTokenFilePath(serverURL string, req *exchange.ExchangeRequest) (string, error) {
	tokensDir, err := GetTokensDir(serverURL)
	if err != nil {
		return "", err
	}
	hash := HashExchangeRequest(req)
	return filepath.Join(tokensDir, hash+".json"), nil
}

// SaveExchangedToken saves an exchanged token to the server's token cache.
func SaveExchangedToken(serverURL string, req *exchange.ExchangeRequest, token string, expiresAt time.Time) error {
	tokenPath, err := getTokenFilePath(serverURL, req)
	if err != nil {
		return err
	}

	// Ensure the tokens directory exists
	tokensDir := filepath.Dir(tokenPath)
	if err := os.MkdirAll(tokensDir, 0o700); err != nil {
		return fmt.Errorf("creating tokens directory: %w", err)
	}

	cached := &CachedToken{
		Token:     token,
		ExpiresAt: expiresAt,
		Spec:      req,
	}

	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling token: %w", err)
	}

	// Atomic write
	tempPath := tokenPath + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o600); err != nil {
		return fmt.Errorf("writing token file: %w", err)
	}

	if err := os.Rename(tempPath, tokenPath); err != nil {
		os.Remove(tempPath) //nolint:errcheck,gosec
		return fmt.Errorf("renaming token file: %w", err)
	}

	return nil
}

// LoadExchangedToken loads a cached exchanged token for a specific server and request.
// Returns the token and its expiry time if found and not expired.
func LoadExchangedToken(serverURL string, req *exchange.ExchangeRequest) (string, time.Time, error) {
	tokenPath, err := getTokenFilePath(serverURL, req)
	if err != nil {
		return "", time.Time{}, err
	}

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", time.Time{}, fmt.Errorf("no cached token found")
		}
		return "", time.Time{}, fmt.Errorf("reading token file: %w", err)
	}

	var cached CachedToken
	if err := json.Unmarshal(data, &cached); err != nil {
		return "", time.Time{}, fmt.Errorf("parsing token file: %w", err)
	}

	if time.Now().After(cached.ExpiresAt) {
		// Token is expired - remove it and return error
		os.Remove(tokenPath) //nolint:errcheck,gosec
		return "", time.Time{}, fmt.Errorf("cached token is expired")
	}

	return cached.Token, cached.ExpiresAt, nil
}

// LoadExchangedTokenWithRenewal loads a cached exchanged token, automatically
// re-exchanging it if it's about to expire (within RenewalThreshold).
// Returns the token, expiry time, whether renewal was performed, and any error.
// This function opportunistically cleans up expired tokens with ~10% probability.
func LoadExchangedTokenWithRenewal(ctx context.Context, serverURL string, req *exchange.ExchangeRequest) (token string, expiresAt time.Time, renewed bool, err error) {
	// Opportunistic cleanup (~10% of calls)
	//nolint:gosec // not used for crypto, just to randomize opportunistic cleanup
	if rand.Intn(cleanupProbability) == 0 {
		go CleanExpiredTokens(serverURL) //nolint:errcheck
	}

	tokenPath, err := getTokenFilePath(serverURL, req)
	if err != nil {
		return "", time.Time{}, false, err
	}

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No cached token - need to exchange
			return exchangeAndCache(ctx, serverURL, req)
		}
		return "", time.Time{}, false, fmt.Errorf("reading token file: %w", err)
	}

	var cached CachedToken
	if err := json.Unmarshal(data, &cached); err != nil {
		// Invalid cache file - remove and re-exchange
		os.Remove(tokenPath) //nolint:errcheck,gosec
		return exchangeAndCache(ctx, serverURL, req)
	}

	now := time.Now()

	// If token is still valid and not near expiry, return it
	if now.Before(cached.ExpiresAt) && time.Until(cached.ExpiresAt) > RenewalThreshold {
		return cached.Token, cached.ExpiresAt, false, nil
	}

	// Token is expired or about to expire - re-exchange
	if now.After(cached.ExpiresAt) {
		// Token is expired - must re-exchange
		os.Remove(tokenPath) //nolint:errcheck,gosec
	}

	// Re-exchange
	newToken, newExp, didRenew, err := exchangeAndCache(ctx, serverURL, req)
	if err != nil {
		// If token is still valid but renewal failed, return the old token
		if now.Before(cached.ExpiresAt) {
			return cached.Token, cached.ExpiresAt, false, nil
		}
		return "", time.Time{}, false, err
	}

	return newToken, newExp, didRenew, nil
}

// exchangeAndCache performs a token exchange and caches the result.
func exchangeAndCache(ctx context.Context, serverURL string, req *exchange.ExchangeRequest) (token string, expiresAt time.Time, renewed bool, err error) {
	// First, load the identity token (with renewal if needed)
	identityToken, _, _, err := LoadIdentityWithRenewal(ctx, serverURL)
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("loading identity token: %w", err)
	}

	// Perform the exchange with a fresh request to avoid mutating the caller's pointer
	exchangeReq := &exchange.ExchangeRequest{
		SubjectToken: identityToken,
		Audience:     req.Audience,
		Scope:        req.Scope,
		Resource:     req.Resource,
	}
	resp, err := exchange.NewClient(serverURL).ExchangeToken(ctx, exchangeReq)
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("exchanging token: %w", err)
	}

	// Calculate expiry
	expiresAt = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)

	// Cache the token. Don't fail on error - we still have a valid token,
	// it just won't be cached for next time.
	_ = SaveExchangedToken(serverURL, req, resp.AccessToken, expiresAt) //nolint:errcheck

	return resp.AccessToken, expiresAt, true, nil
}

// DeleteExchangedToken removes a specific cached token.
func DeleteExchangedToken(serverURL string, req *exchange.ExchangeRequest) error {
	tokenPath, err := getTokenFilePath(serverURL, req)
	if err != nil {
		return err
	}

	if err := os.Remove(tokenPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("deleting token file: %w", err)
	}

	return nil
}

// CleanExpiredTokens removes all expired tokens from a server's token cache.
// Returns the number of tokens removed.
func CleanExpiredTokens(serverURL string) (int, error) {
	tokensDir, err := GetTokensDir(serverURL)
	if err != nil {
		return 0, err
	}

	entries, err := os.ReadDir(tokensDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // No tokens directory yet
		}
		return 0, fmt.Errorf("reading tokens directory: %w", err)
	}

	removed := 0
	now := time.Now()

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		tokenPath := filepath.Join(tokensDir, entry.Name())
		data, err := os.ReadFile(tokenPath)
		if err != nil {
			continue // Skip files we can't read
		}

		var cached CachedToken
		if err := json.Unmarshal(data, &cached); err != nil {
			// Invalid file - remove it
			os.Remove(tokenPath) //nolint:errcheck,gosec
			removed++
			continue
		}

		if now.After(cached.ExpiresAt) {
			os.Remove(tokenPath) //nolint:errcheck,gosec
			removed++
		}
	}

	return removed, nil
}

// CleanAllExpiredTokens removes expired tokens from all server sessions.
// Returns the total number of tokens removed.
func CleanAllExpiredTokens() (int, error) {
	sessions, _, err := ListSessions()
	if err != nil {
		return 0, err
	}

	totalRemoved := 0
	for serverURL := range sessions {
		removed, err := CleanExpiredTokens(serverURL)
		if err != nil {
			continue // Skip servers with errors
		}
		totalRemoved += removed
	}

	return totalRemoved, nil
}

// GetToken is a convenience function for apps to get a token for a specific audience.
// It uses the default session's server and automatically handles caching and renewal.
//
// Example usage:
//
//	token, err := credentials.GetToken(ctx, "https://api.example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Use token...
func GetToken(ctx context.Context, audience ...string) (string, error) {
	return GetTokenWithOptions(ctx, &exchange.ExchangeRequest{Audience: audience})
}

// GetTokenWithOptions is like GetToken but allows specifying full exchange options.
//
// Example usage:
//
//	token, err := credentials.GetTokenWithOptions(ctx, &exchange.ExchangeRequest{
//	    Audience: []string{"https://api.example.com"},
//	    Scope:    []string{"read", "write"},
//	})
func GetTokenWithOptions(ctx context.Context, req *exchange.ExchangeRequest) (string, error) {
	// Get the default session to find the server URL
	_, serverURL, err := GetDefaultSession()
	if err != nil {
		return "", fmt.Errorf("no default session configured (run 'carabiner login' first): %w", err)
	}

	token, _, _, err := LoadExchangedTokenWithRenewal(ctx, serverURL, req)
	if err != nil {
		return "", err
	}

	return token, nil
}

// GetTokenForServer is like GetToken but allows specifying a specific server.
func GetTokenForServer(ctx context.Context, serverURL string, audience ...string) (string, error) {
	return GetTokenForServerWithOptions(ctx, serverURL, &exchange.ExchangeRequest{Audience: audience})
}

// GetTokenForServerWithOptions is like GetTokenWithOptions but allows specifying a specific server.
func GetTokenForServerWithOptions(ctx context.Context, serverURL string, req *exchange.ExchangeRequest) (string, error) {
	token, _, _, err := LoadExchangedTokenWithRenewal(ctx, serverURL, req)
	if err != nil {
		return "", err
	}

	return token, nil
}
