// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// ActionsTokenRetriever retrieves OIDC tokens from GitHub Actions
type ActionsTokenRetriever struct {
	RequestURL   string // From ACTIONS_ID_TOKEN_REQUEST_URL
	RequestToken string // From ACTIONS_ID_TOKEN_REQUEST_TOKEN
	Audience     string // Optional audience for the token
}

// tokenResponse represents the response from GitHub Actions OIDC endpoint
type tokenResponse struct {
	Value string `json:"value"` // The OIDC token
}

// NewActionsTokenRetriever creates a token retriever from environment variables
func NewActionsTokenRetriever(audience string) (*ActionsTokenRetriever, error) {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	if requestURL == "" {
		return nil, fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL environment variable not set (are you running in GitHub Actions?)")
	}

	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestToken == "" {
		return nil, fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable not set (are you running in GitHub Actions?)")
	}

	return &ActionsTokenRetriever{
		RequestURL:   requestURL,
		RequestToken: requestToken,
		Audience:     audience,
	}, nil
}

// GetToken retrieves an OIDC token from GitHub Actions
func (a *ActionsTokenRetriever) GetToken(ctx context.Context) (string, error) {
	// Build request URL with optional audience
	reqURL := a.RequestURL
	if a.Audience != "" {
		parsedURL, err := url.Parse(reqURL)
		if err != nil {
			return "", fmt.Errorf("parsing request URL: %w", err)
		}
		query := parsedURL.Query()
		query.Set("audience", a.Audience)
		parsedURL.RawQuery = query.Encode()
		reqURL = parsedURL.String()
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	// Add authorization header with the request token
	req.Header.Set("Authorization", "Bearer "+a.RequestToken)

	// Send request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting token: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub Actions API returned %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}

	if tokenResp.Value == "" {
		return "", fmt.Errorf("empty token in response")
	}

	return tokenResp.Value, nil
}

// IsGitHubActions checks if we're running in GitHub Actions environment
func IsGitHubActions() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true" &&
		os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" &&
		os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != ""
}
