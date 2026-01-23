// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/oauth2"
)

// OAuthFlow orchestrates the browser-based OAuth login
type OAuthFlow struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	IssuerURL    string
	Scopes       []string
	Timeout      time.Duration // Timeout for OAuth flow (default: 2 minutes)
}

// LoginResult contains the OAuth tokens
type LoginResult struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// Login initiates browser-based OAuth flow with PKCE
func (f *OAuthFlow) Login(ctx context.Context) (*LoginResult, error) {
	// Set default timeout if not specified
	if f.Timeout == 0 {
		f.Timeout = 2 * time.Minute
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, f.Timeout)
	defer cancel()

	// Generate PKCE challenge
	pkce, err := GeneratePKCEChallenge()
	if err != nil {
		return nil, fmt.Errorf("generating PKCE challenge: %w", err)
	}

	// Generate state for CSRF protection
	state, err := generateState()
	if err != nil {
		return nil, fmt.Errorf("generating state: %w", err)
	}

	// Start local callback server
	callbackServer, err := newCallbackServer()
	if err != nil {
		return nil, fmt.Errorf("starting callback server: %w", err)
	}
	defer callbackServer.shutdown(context.Background()) //nolint:errcheck

	callbackServer.start()
	redirectURL := callbackServer.getRedirectURL()

	// Configure OAuth2
	oauth2Config := &oauth2.Config{
		ClientID:     f.ClientID,
		ClientSecret: f.ClientSecret, // Optional: only needed for Web App type OAuth clients
		Endpoint: oauth2.Endpoint{
			AuthURL:  f.AuthURL,
			TokenURL: f.TokenURL,
		},
		RedirectURL: redirectURL,
		Scopes:      f.Scopes,
	}

	// Build authorization URL with PKCE
	authURL := oauth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", pkce.Challenge),
		oauth2.SetAuthURLParam("code_challenge_method", pkce.Method),
	)

	// Open browser
	fmt.Printf("Opening browser for authentication...\n")
	fmt.Printf("If the browser doesn't open automatically, please visit:\n%s\n\n", authURL)

	if err := openBrowser(authURL); err != nil {
		fmt.Printf("Failed to open browser automatically: %v\n", err)
	}

	// Wait for the callback from the browser to complete
	result, err := callbackServer.waitForCallback(ctx)
	if err != nil {
		if err == context.DeadlineExceeded {
			return nil, fmt.Errorf("authentication timed out after %v. Please try again", f.Timeout)
		}
		return nil, fmt.Errorf("waiting for callback: %w", err)
	}

	// Check for OAuth error
	if result.Error != "" {
		return nil, fmt.Errorf("OAuth error talking to identity provider: %s", result.Error)
	}

	// Validate state
	if result.State != state {
		return nil, fmt.Errorf("state mismatch: potential CSRF attack")
	}

	// Exchange authorization code for tokens
	token, err := oauth2Config.Exchange(
		ctx, result.Code, oauth2.SetAuthURLParam("code_verifier", pkce.Verifier),
	)
	if err != nil {
		return nil, fmt.Errorf("exchanging token with ID provider: %w", err)
	}

	// Extract ID token
	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		return nil, fmt.Errorf("no ID token in response")
	}

	return &LoginResult{
		IDToken:      idToken,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}, nil
}

// generateState generates a random state parameter for CSRF protection
func generateState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// openBrowser opens the URL in the system's default browser
func openBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	return cmd.Start()
}
