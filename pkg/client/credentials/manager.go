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
)

// TokenSource is an interface for retrieving tokens, similar to oauth2.TokenSource.
type TokenSource interface {
	// Token returns a valid token or an error.
	Token(ctx context.Context) (string, error)
}

// ExchangeSpec defines the parameters for a token exchange.
type ExchangeSpec struct {
	Audience []string
	Scope    []string
	Resource []string
}

// managedToken holds the state for a single exchanged token.
type managedToken struct {
	mu sync.RWMutex
	// Token data
	token      string
	expiresAt  time.Time
	spec       ExchangeSpec
	refreshing bool
	lastError  error
}

// Manager manages credential sessions by handling token lifecycle.
// It uses a central identity token to exchange for short lived
// audience-specific tokens.
type Manager struct {
	mu           sync.RWMutex
	centralToken string
	server       string
	client       *exchange.Client
	tokens       map[string]*managedToken

	// refreshBuffer is the fraction of lifetime remaining to trigger refresh
	// (e.g., 0.2 = refresh at 80% of lifetime)
	refreshBuffer float64

	// maxRetries controls how many times we'll attempt exchanging when an error
	maxRetries int

	retryInterval time.Duration // Initial retry interval (exponential backoff)
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewManager creates a new credential manager.
// The centralToken is the long-lived JWT used as the identity for all exchanges.
// Use WithServer to configure the deadrop exchange server URL.
func NewManager(ctx context.Context, centralToken string, opts ...Option) (*Manager, error) {
	if centralToken == "" {
		return nil, errors.New("central token is required")
	}

	// Validate central token is not expired
	exp, err := extractExpiry(centralToken)
	if err != nil {
		return nil, fmt.Errorf("invalid central token: %w", err)
	}
	if time.Now().After(exp) {
		return nil, errors.New("central token is expired")
	}

	ctx, cancel := context.WithCancel(ctx)

	m := &Manager{
		centralToken:  centralToken,
		tokens:        make(map[string]*managedToken),
		refreshBuffer: 0.2, // Default: refresh when 20% of lifetime remains
		maxRetries:    5,
		retryInterval: time.Second,
		ctx:           ctx,
		cancel:        cancel,
	}

	for _, opt := range opts {
		opt(m)
	}

	// Validate server is configured
	if m.server == "" {
		cancel()
		return nil, errors.New("server URL is required (use WithServer option)")
	}

	// Initialize exchange client if not already set by options
	if m.client == nil {
		m.client = exchange.NewClient(m.server)
	}

	return m, nil
}

// Register adds a new exchange specification struct and immediately calls its
// endpoint to exchange a token.
//
// The id is used to retrieve the token later via Token() or TokenSource().
func (m *Manager) Register(ctx context.Context, id string, spec ExchangeSpec) error {
	if id == "" {
		return errors.New("token id is required")
	}
	if len(spec.Audience) == 0 {
		return errors.New("at least one audience is required")
	}

	m.mu.Lock()
	if _, exists := m.tokens[id]; exists {
		m.mu.Unlock()
		return fmt.Errorf("token with id %q already registered", id)
	}

	mt := &managedToken{
		spec: spec,
	}
	m.tokens[id] = mt
	m.mu.Unlock()

	// Perform initial exchange early, if the exchange fails, the new
	// token registration entirely fails.
	if err := m.refreshToken(ctx, id, mt); err != nil {
		m.mu.Lock()
		delete(m.tokens, id)
		m.mu.Unlock()
		return fmt.Errorf("initial token exchange failed: %w", err)
	}

	return nil
}

// Token returns the token for the given id.
// If the token is expired or about to expire, it will be refreshed.
func (m *Manager) Token(ctx context.Context, id string) (string, error) {
	m.mu.RLock()
	mt, exists := m.tokens[id]
	m.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("no token registered with id %q", id)
	}

	mt.mu.RLock()
	token := mt.token
	expiresAt := mt.expiresAt
	refreshing := mt.refreshing
	lastError := mt.lastError
	mt.mu.RUnlock()

	now := time.Now()

	// Calculate refresh threshold
	lifetime := time.Until(expiresAt)
	refreshThreshold := expiresAt.Add(-time.Duration(float64(lifetime) * m.refreshBuffer))

	// If token is still valid
	if now.Before(expiresAt) && token != "" {
		// ... but it is approaching its expiry time
		// and not already refreshing
		if now.After(refreshThreshold) && !refreshing {
			go m.backgroundRefresh(id, mt)
		}
		return token, nil
	}

	// Token is expired or missing - need to refresh synchronously
	if refreshing {
		// Wait for ongoing refresh to complete
		return m.waitForRefresh(ctx, id, mt)
	}

	// Perform synchronous refresh with retries
	if err := m.refreshToken(ctx, id, mt); err != nil {
		// If we have a stale token and the error is transient, we could return it
		// But per requirements, we should retry until success or context cancellation
		return "", fmt.Errorf("token refresh failed: %w", err)
	}

	mt.mu.RLock()
	token = mt.token
	lastError = mt.lastError
	mt.mu.RUnlock()

	if lastError != nil {
		return "", lastError
	}

	return token, nil
}

// TokenSource returns a TokenSource for the given id.
func (m *Manager) TokenSource(id string) (TokenSource, error) {
	m.mu.RLock()
	_, exists := m.tokens[id]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no token registered with id %q", id)
	}

	return &managerTokenSource{
		manager: m,
		id:      id,
	}, nil
}

// Close stops all background refresh goroutines and releases resources.
func (m *Manager) Close() error {
	m.cancel()
	return nil
}

// refreshToken performs the actual token exchange with retry logic.
func (m *Manager) refreshToken(ctx context.Context, id string, mt *managedToken) error {
	mt.mu.Lock()
	if mt.refreshing {
		mt.mu.Unlock()
		_, err := m.waitForRefresh(ctx, id, mt)
		return err
	}
	mt.refreshing = true
	spec := mt.spec
	mt.mu.Unlock()

	defer func() {
		mt.mu.Lock()
		mt.refreshing = false
		mt.mu.Unlock()
	}()

	req := &exchange.ExchangeRequest{
		SubjectToken: m.centralToken,
		Audience:     spec.Audience,
		Scope:        spec.Scope,
		Resource:     spec.Resource,
	}

	var lastErr error
	retryInterval := m.retryInterval

	// Run the refresh attempts, backing off on err
	for attempt := 0; attempt <= m.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-m.ctx.Done():
				return m.ctx.Err()
			case <-time.After(retryInterval):
				retryInterval *= 2 // Exponential backoff
			}
		}

		resp, err := m.client.ExchangeToken(ctx, req)
		if err != nil {
			lastErr = err
			continue
		}

		// Calculate expiry time
		expiresAt := time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)

		mt.mu.Lock()
		mt.token = resp.AccessToken
		mt.expiresAt = expiresAt
		mt.lastError = nil
		mt.mu.Unlock()

		return nil
	}

	mt.mu.Lock()
	mt.lastError = lastErr
	mt.mu.Unlock()

	return fmt.Errorf("exchange failed after %d attempts: %w", m.maxRetries+1, lastErr)
}

// backgroundRefresh performs a token refresh in the background.
func (m *Manager) backgroundRefresh(id string, mt *managedToken) {
	mt.mu.Lock()
	if mt.refreshing {
		mt.mu.Unlock()
		return
	}
	mt.refreshing = true
	mt.mu.Unlock()

	// Use the manager's context for background operations
	_ = m.refreshToken(m.ctx, id, mt)
}

// waitForRefresh waits for an ongoing refresh to complete.
func (m *Manager) waitForRefresh(ctx context.Context, id string, mt *managedToken) (string, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-m.ctx.Done():
			return "", m.ctx.Err()
		case <-ticker.C:
			mt.mu.RLock()
			refreshing := mt.refreshing
			token := mt.token
			expiresAt := mt.expiresAt
			lastError := mt.lastError
			mt.mu.RUnlock()

			if !refreshing {
				if lastError != nil {
					return "", lastError
				}
				if time.Now().Before(expiresAt) && token != "" {
					return token, nil
				}
				// Refresh completed but token still invalid - retry
				return m.Token(ctx, id)
			}
		}
	}
}

// managerTokenSource implements TokenSource using the Manager.
type managerTokenSource struct {
	manager *Manager
	id      string
}

func (ts *managerTokenSource) Token(ctx context.Context) (string, error) {
	return ts.manager.Token(ctx, ts.id)
}

// extractExpiry extracts the expiry time from a JWT token.
func extractExpiry(token string) (time.Time, error) {
	parts := splitJWT(token)
	if len(parts) != 3 {
		return time.Time{}, errors.New("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("decoding payload: %w", err)
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("parsing claims: %w", err)
	}

	if claims.Exp == 0 {
		return time.Time{}, errors.New("no expiry claim in token")
	}

	return time.Unix(claims.Exp, 0), nil
}

// splitJWT splits a JWT into its parts without validation.
func splitJWT(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}
