// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package exchange

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client handles token exchange with deadrop server
type Client struct {
	ServerURL  string // e.g., https://auth.carabiner.dev
	HTTPClient *http.Client
}

// NewClient creates a new token exchange client
func NewClient(serverURL string) *Client {
	return &Client{
		ServerURL: strings.TrimSuffix(serverURL, "/"),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ExchangeToken performs RFC 8693 token exchange
func (c *Client) ExchangeToken(ctx context.Context, req *ExchangeRequest) (*ExchangeResponse, error) {
	// Validate request
	if err := c.validateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Build form data
	formData := url.Values{}
	formData.Set("grant_type", GrantTypeTokenExchange)
	formData.Set("subject_token", req.SubjectToken)
	formData.Set("subject_token_type", req.SubjectTokenType)
	formData.Set("requested_token_type", req.RequestedTokenType)

	// Add audience - multiple parameters per RFC 8693
	for _, aud := range req.Audience {
		formData.Add("audience", aud)
	}

	// Add scope - space-delimited string per RFC 8693
	if len(req.Scope) > 0 {
		formData.Set("scope", strings.Join(req.Scope, " "))
	}

	// Actor credential (RFC 8693 section 2.1): the party acting on behalf of
	// the subject. Sent only when set; the type defaults server-side to JWT.
	if req.ActorToken != "" {
		formData.Set("actor_token", req.ActorToken)
		if req.ActorTokenType != "" {
			formData.Set("actor_token_type", req.ActorTokenType)
		}
	}

	// Add resource - multiple parameters per RFC 8693
	for _, res := range req.Resource {
		formData.Add("resource", res)
	}

	// Create HTTP request
	tokenURL := c.ServerURL + "/token"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	// Send request
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending request to %s: %w", tokenURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	// Handle non-200 responses
	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp.StatusCode, body)
	}

	// Parse successful response
	var exchangeResp ExchangeResponse
	if err := json.Unmarshal(body, &exchangeResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &exchangeResp, nil
}

// validateRequest validates the exchange request
func (c *Client) validateRequest(req *ExchangeRequest) error {
	if req.SubjectToken == "" {
		return fmt.Errorf("subject_token is required")
	}

	if req.SubjectTokenType == "" {
		req.SubjectTokenType = TokenTypeJWT // Default
	}

	if req.RequestedTokenType == "" {
		req.RequestedTokenType = TokenTypeJWT // Default
	}

	if len(req.Audience) == 0 {
		return fmt.Errorf("audience is required")
	}

	return nil
}

// RenewToken renews an existing Carabiner token.
// The token must have been issued by the server and may be expired (within grace period).
func (c *Client) RenewToken(ctx context.Context, token string) (*ExchangeResponse, error) {
	if token == "" {
		return nil, fmt.Errorf("token is required")
	}

	// Build form data
	formData := url.Values{}
	formData.Set("token", token)

	// Create HTTP request
	renewURL := c.ServerURL + "/renew"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, renewURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	// Send request
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending request to %s: %w", renewURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	// Handle non-200 responses
	if resp.StatusCode != http.StatusOK {
		return nil, c.handleRenewErrorResponse(resp.StatusCode, body)
	}

	// Parse successful response
	var renewResp ExchangeResponse
	if err := json.Unmarshal(body, &renewResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &renewResp, nil
}

// handleErrorResponse parses and formats error responses
func (c *Client) handleErrorResponse(statusCode int, body []byte) error {
	// Try to parse as OAuth error
	var errorResp ErrorResponse
	if err := json.Unmarshal(body, &errorResp); err == nil && errorResp.Error != "" {
		detail := fmt.Errorf("token exchange failed (HTTP %d): %s - %s",
			statusCode, errorResp.Error, errorResp.ErrorDescription)
		// When the server rejects the subject identity itself, the caller must
		// re-authenticate; flag it as such so it can be detected with errors.Is.
		if isAuthErrorCode(errorResp.Error) {
			return fmt.Errorf("%w: %w", ErrAuthRequired, detail)
		}
		return detail
	}

	// An unauthorized response with no parseable OAuth body is still an auth
	// failure the user resolves by logging in again.
	if statusCode == http.StatusUnauthorized {
		return fmt.Errorf("%w: token exchange failed (HTTP %d): %s",
			ErrAuthRequired, statusCode, string(body))
	}

	// Fallback to generic error
	return fmt.Errorf("token exchange failed (HTTP %d): %s", statusCode, string(body))
}

// handleRenewErrorResponse parses and formats renewal error responses
func (c *Client) handleRenewErrorResponse(statusCode int, body []byte) error {
	// Try to parse as OAuth error
	var errorResp ErrorResponse
	if err := json.Unmarshal(body, &errorResp); err == nil && errorResp.Error != "" {
		// Check for token_expired error which means the token is too old to renew
		if errorResp.Error == "token_expired" {
			return &TokenExpiredError{
				Message: errorResp.ErrorDescription,
			}
		}
		return fmt.Errorf("token renewal failed (HTTP %d): %s - %s",
			statusCode, errorResp.Error, errorResp.ErrorDescription)
	}

	// Fallback to generic error
	return fmt.Errorf("token renewal failed (HTTP %d): %s", statusCode, string(body))
}

// TokenExpiredError is returned when a token is too old to be renewed.
// The user must log in again.
type TokenExpiredError struct {
	Message string
}

func (e *TokenExpiredError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "token is too old to renew, please log in again"
}
