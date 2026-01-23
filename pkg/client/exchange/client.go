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

	// Add resource - multiple parameters per RFC 8693
	for _, res := range req.Resource {
		formData.Add("resource", res)
	}

	// Create HTTP request
	tokenURL := c.ServerURL + "/token"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(formData.Encode()))
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

// handleErrorResponse parses and formats error responses
func (c *Client) handleErrorResponse(statusCode int, body []byte) error {
	// Try to parse as OAuth error
	var errorResp ErrorResponse
	if err := json.Unmarshal(body, &errorResp); err == nil && errorResp.Error != "" {
		return fmt.Errorf("token exchange failed (HTTP %d): %s - %s",
			statusCode, errorResp.Error, errorResp.ErrorDescription)
	}

	// Fallback to generic error
	return fmt.Errorf("token exchange failed (HTTP %d): %s", statusCode, string(body))
}
