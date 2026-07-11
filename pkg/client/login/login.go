// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package login is the client for the carabiner login service's OAuth
// authorization-code flow. Web apps and CLIs use it to (1) send a user's browser
// to login to authenticate and consent, and (2) redeem the returned one-time
// code for a carabiner JWT over a back-channel, so the token never rides in a
// browser-visible URL.
//
// Typical web-app use:
//
//	pkce, _ := login.GeneratePKCE()
//	// stash pkce.Verifier and a random state in the app's (sealed) session, then:
//	u, _ := login.AuthCodeURL(loginURL, login.AuthCodeParams{
//		CallbackURL: appCallback,
//		Scopes:      []string{"identities"},
//		State:       state,
//		Challenge:   pkce.Challenge,
//	})
//	// redirect the browser to u. On the callback (?code=&state=), after checking
//	// state, redeem over the back-channel:
//	tok, _ := login.NewClient(loginURL).Redeem(ctx, code, pkce.Verifier)
package login

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

const defaultTimeout = 30 * time.Second

// AuthCodeParams are the inputs to AuthCodeURL.
type AuthCodeParams struct {
	// CallbackURL is where login sends the browser back with the ?code=.
	CallbackURL string
	// Scopes are the data scopes the app requests. Optional; login applies the
	// app's default scopes when empty.
	Scopes []string
	// State is an opaque value login echoes back on the callback so the app can
	// correlate it with the browser session. Optional but recommended.
	State string
	// Challenge is the PKCE S256 code_challenge (see GeneratePKCE).
	Challenge string
}

// AuthCodeURL builds the URL to send the user's browser to in order to begin an
// authorization-code login against the login service at loginURL.
func AuthCodeURL(loginURL string, p AuthCodeParams) (string, error) {
	if p.CallbackURL == "" {
		return "", fmt.Errorf("callback URL is required")
	}
	if p.Challenge == "" {
		return "", fmt.Errorf("PKCE challenge is required")
	}
	u, err := url.Parse(loginURL)
	if err != nil {
		return "", fmt.Errorf("parsing login URL: %w", err)
	}

	q := u.Query()
	q.Set("callback_url", p.CallbackURL)
	if len(p.Scopes) > 0 {
		q.Set("scope", strings.Join(p.Scopes, " "))
	}
	q.Set("response_type", "code")
	q.Set("code_challenge", p.Challenge)
	q.Set("code_challenge_method", "S256")
	if p.State != "" {
		q.Set("state", p.State)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Client redeems authorization codes at the login service's token endpoint.
type Client struct {
	LoginURL   string // e.g. https://login.carabiner.dev
	HTTPClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the HTTP client used for redemption.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.HTTPClient = hc }
}

// NewClient creates a login client for the given login service base URL.
func NewClient(loginURL string, opts ...Option) *Client {
	c := &Client{
		LoginURL:   strings.TrimSuffix(loginURL, "/"),
		HTTPClient: &http.Client{Timeout: defaultTimeout},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// TokenResponse is the successful result of redeeming an authorization code.
type TokenResponse struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int64
}

// Redeem exchanges an authorization code (received on the app's callback) plus
// the PKCE verifier for a carabiner JWT, over a back-channel POST to
// /auth/token. The token is never exposed in a browser-visible URL.
func (c *Client) Redeem(ctx context.Context, code, verifier string) (*TokenResponse, error) {
	if code == "" || verifier == "" {
		return nil, fmt.Errorf("code and verifier are required")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", verifier)

	endpoint := c.LoginURL + "/auth/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request to %s: %w", endpoint, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseError(resp.StatusCode, body)
	}

	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint returned no access_token")
	}
	return &TokenResponse{
		AccessToken: tr.AccessToken,
		TokenType:   tr.TokenType,
		ExpiresIn:   tr.ExpiresIn,
	}, nil
}

// Error is a structured error returned by the login token endpoint (RFC 6749
// §5.2 style: an "error" code and optional "error_description").
type Error struct {
	StatusCode  int
	Code        string // e.g. "invalid_grant", "invalid_request"
	Description string
}

func (e *Error) Error() string {
	switch {
	case e.Code != "" && e.Description != "":
		return fmt.Sprintf("login token endpoint (HTTP %d): %s: %s", e.StatusCode, e.Code, e.Description)
	case e.Code != "":
		return fmt.Sprintf("login token endpoint (HTTP %d): %s", e.StatusCode, e.Code)
	default:
		return fmt.Sprintf("login token endpoint (HTTP %d)", e.StatusCode)
	}
}

// parseError converts a non-200 token-endpoint response into an *Error.
func parseError(status int, body []byte) error {
	e := &Error{StatusCode: status}
	var payload struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.Error != "" {
		e.Code = payload.Error
		e.Description = payload.Description
	} else {
		e.Description = strings.TrimSpace(string(body))
	}
	return e
}
