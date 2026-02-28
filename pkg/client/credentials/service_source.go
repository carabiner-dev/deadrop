// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
	"github.com/chainguard-dev/clog"
)

// ServiceTokenSourceOption configures a ServiceTokenSource.
type ServiceTokenSourceOption func(*ServiceTokenSource)

// WithServiceIdentitySource overrides the default identity token source
// used to obtain the subject token for exchange.
func WithServiceIdentitySource(source TokenSource) ServiceTokenSourceOption {
	return func(s *ServiceTokenSource) {
		if source != nil {
			s.source = source
		}
	}
}

// WithServicePersistence enables token persistence in the server's session
// directory. When enabled, exchanged tokens are cached to disk and loaded
// on subsequent calls, surviving process restarts.
func WithServicePersistence() ServiceTokenSourceOption {
	return func(s *ServiceTokenSource) {
		s.persist = true
	}
}

// WithServiceRefreshBuffer sets the fraction of token lifetime remaining
// that triggers a renewal. Default is 0.2 (renew when 20% of lifetime remains).
func WithServiceRefreshBuffer(buffer float64) ServiceTokenSourceOption {
	return func(s *ServiceTokenSource) {
		if buffer > 0 && buffer < 1 {
			s.refreshBuffer = buffer
		}
	}
}

// ServiceTokenSource is a TokenSource that exchanges the main Carabiner identity
// token for a service-specific token based on an ExchangeRequest. It manages the
// lifecycle of the exchanged token, automatically renewing it when less than 20%
// of its lifetime remains (configurable via WithServiceRefreshBuffer).
//
// The ExchangeRequest serves as a template: its Audience, Scope, Resource, and
// token type fields are preserved, while SubjectToken is set automatically from
// the identity source on each exchange.
//
// Example usage:
//
//	source, err := credentials.NewServiceTokenSource(
//	    &exchange.ExchangeRequest{
//	        Audience: []string{"https://api.example.com"},
//	    },
//	    "https://auth.carabiner.dev",
//	    credentials.WithServicePersistence(),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	token, err := source.Token(ctx)
type ServiceTokenSource struct {
	mu        sync.RWMutex
	request   *exchange.ExchangeRequest
	source    TokenSource
	serverURL string
	client    *exchange.Client

	// Cached token state
	token      string
	expiresAt  time.Time
	issuedAt   time.Time
	refreshing bool

	// Configuration
	refreshBuffer float64
	persist       bool
}

// NewServiceTokenSource creates a ServiceTokenSource that exchanges the main
// Carabiner identity for a service-specific token matching the given ExchangeRequest.
//
// The request serves as a template: SubjectToken is ignored and set automatically
// from the identity source on each exchange. All other fields (Audience, Scope,
// Resource, SubjectTokenType, RequestedTokenType) are forwarded as-is.
//
// The serverURL is the deadrop exchange server URL.
// Use options to configure identity source, persistence, and refresh behavior.
func NewServiceTokenSource(req *exchange.ExchangeRequest, serverURL string, opts ...ServiceTokenSourceOption) (*ServiceTokenSource, error) {
	if req == nil {
		return nil, errors.New("exchange request is required")
	}
	if len(req.Audience) == 0 {
		return nil, errors.New("at least one audience is required in the exchange request")
	}
	if serverURL == "" {
		return nil, errors.New("server URL is required")
	}

	s := &ServiceTokenSource{
		request:       req,
		serverURL:     serverURL,
		client:        exchange.NewClient(serverURL),
		refreshBuffer: 0.2,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.source == nil {
		defaultSource, err := DefaultTokenSource()
		if err != nil {
			return nil, fmt.Errorf("creating default identity source: %w", err)
		}
		s.source = defaultSource
	}

	return s, nil
}

// Token returns a valid exchanged service token. If the current token has less
// than 20% of its lifetime remaining, it is automatically renewed in the
// background. If no valid token is available, a new exchange is performed
// synchronously.
func (s *ServiceTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.RLock()
	token := s.token
	expiresAt := s.expiresAt
	issuedAt := s.issuedAt
	refreshing := s.refreshing
	s.mu.RUnlock()

	now := time.Now()

	// If we have a valid in-memory token
	if token != "" && now.Before(expiresAt) {
		clog.FromContext(ctx).Debug("Using cached token from memory", "expires_in", time.Until(expiresAt).Round(time.Second))
		if shouldRefresh(now, issuedAt, expiresAt, s.refreshBuffer) && !refreshing {
			clog.FromContext(ctx).Debug("Token near expiry, triggering background refresh")
			go s.backgroundRefresh()
		}
		return token, nil
	}

	// Try to load from persistence if we don't have an in-memory token
	if s.persist && token == "" {
		if t, exp, err := LoadExchangedToken(s.serverURL, s.request); err == nil && now.Before(exp) {
			iat := extractTokenIssuedAt(t, exp)
			s.mu.Lock()
			s.token = t
			s.expiresAt = exp
			s.issuedAt = iat
			s.mu.Unlock()

			clog.FromContext(ctx).Debug("Using cached token from disk", "expires_in", time.Until(exp).Round(time.Second))

			if !shouldRefresh(now, iat, exp, s.refreshBuffer) {
				return t, nil
			}
			// Loaded but needs refresh - trigger background and return current
			clog.FromContext(ctx).Debug("Token near expiry, triggering background refresh")
			go s.backgroundRefresh()
			return t, nil
		}
	}

	// No valid token - need to exchange synchronously
	if refreshing {
		return s.waitForRefresh(ctx)
	}

	return s.exchangeSync(ctx)
}

// shouldRefresh returns true if the token should be renewed based on the
// fraction of its total lifetime that remains.
func shouldRefresh(now, issuedAt, expiresAt time.Time, buffer float64) bool {
	totalLifetime := expiresAt.Sub(issuedAt)
	if totalLifetime <= 0 {
		return true
	}
	remaining := expiresAt.Sub(now)
	return float64(remaining)/float64(totalLifetime) < buffer
}

// exchangeSync performs a synchronous token exchange.
func (s *ServiceTokenSource) exchangeSync(ctx context.Context) (string, error) {
	s.mu.Lock()
	if s.refreshing {
		s.mu.Unlock()
		return s.waitForRefresh(ctx)
	}
	s.refreshing = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.refreshing = false
		s.mu.Unlock()
	}()

	token, issuedAt, expiresAt, err := s.doExchange(ctx)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	s.token = token
	s.expiresAt = expiresAt
	s.issuedAt = issuedAt
	s.mu.Unlock()

	if s.persist {
		_ = SaveExchangedToken(s.serverURL, s.request, token, expiresAt)
	}

	return token, nil
}

// backgroundRefresh performs a token exchange in the background.
func (s *ServiceTokenSource) backgroundRefresh() {
	s.mu.Lock()
	if s.refreshing {
		s.mu.Unlock()
		return
	}
	s.refreshing = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.refreshing = false
		s.mu.Unlock()
	}()

	token, issuedAt, expiresAt, err := s.doExchange(context.Background())
	if err != nil {
		return // Background refresh failed, will retry on next access
	}

	s.mu.Lock()
	s.token = token
	s.expiresAt = expiresAt
	s.issuedAt = issuedAt
	s.mu.Unlock()

	if s.persist {
		_ = SaveExchangedToken(s.serverURL, s.request, token, expiresAt)
	}
}

// waitForRefresh waits for an ongoing refresh to complete and returns the token.
func (s *ServiceTokenSource) waitForRefresh(ctx context.Context) (string, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			s.mu.RLock()
			refreshing := s.refreshing
			token := s.token
			expiresAt := s.expiresAt
			s.mu.RUnlock()

			if !refreshing {
				if token != "" && time.Now().Before(expiresAt) {
					return token, nil
				}
				// Refresh completed but no valid token - try again
				return s.exchangeSync(ctx)
			}
		}
	}
}

// doExchange performs the actual token exchange against the server.
func (s *ServiceTokenSource) doExchange(ctx context.Context) (token string, issuedAt, expiresAt time.Time, err error) {
	identityToken, err := s.source.Token(ctx)
	if err != nil {
		return "", time.Time{}, time.Time{}, fmt.Errorf("getting identity token: %w", err)
	}

	// Build a fresh request to avoid mutating the shared s.request pointer.
	req := &exchange.ExchangeRequest{
		SubjectToken: identityToken,
		Audience:     s.request.Audience,
		Scope:        s.request.Scope,
		Resource:     s.request.Resource,
	}

	// Debug log to track actual exchange requests
	clog.FromContext(ctx).Debug("Sending token exchange request",
		"server", s.serverURL, "audience", req.Audience, "resources", req.Resource)

	resp, err := s.client.ExchangeToken(ctx, req)
	if err != nil {
		return "", time.Time{}, time.Time{}, fmt.Errorf("exchanging token: %w", err)
	}

	now := time.Now()
	expiresAt = now.Add(time.Duration(resp.ExpiresIn) * time.Second)

	clog.FromContext(ctx).Debug("Token exchange successful", "expires_in_seconds", resp.ExpiresIn)

	return resp.AccessToken, now, expiresAt, nil
}

// extractTokenIssuedAt extracts the issued-at time from a JWT token's iat claim.
// If the iat claim is not present, it returns expiresAt which causes the token
// to be treated as needing immediate refresh.
func extractTokenIssuedAt(token string, expiresAt time.Time) time.Time {
	parts := splitJWT(token)
	if len(parts) != 3 {
		return expiresAt
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return expiresAt
	}

	var claims struct {
		Iat int64 `json:"iat"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return expiresAt
	}

	if claims.Iat > 0 {
		return time.Unix(claims.Iat, 0)
	}

	return expiresAt
}
