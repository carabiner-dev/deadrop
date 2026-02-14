// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/deadrop/pkg/client/config"
	"github.com/carabiner-dev/deadrop/pkg/client/credentials"
	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
	"github.com/carabiner-dev/deadrop/pkg/client/oauth"
	"github.com/spf13/cobra"
)

// CarabinerAudience is the audience used for the central carabiner identity token.
const CarabinerAudience = "carabiner"

var _ command.OptionsSet = (*LoginOptions)(nil)

type LoginOptions struct {
	ServerOptions
	ClientID     string
	ClientSecret string
	Provider     string
	PrintToken   bool
	Force        bool
}

var defaultLoginOptions = LoginOptions{
	Provider:   "google",
	PrintToken: false,
}

// Validate the options set
func (lo *LoginOptions) Validate() error {
	var errs = []error{
		lo.ServerOptions.Validate(),
	}
	return errors.Join(errs...)
}

func (lo *LoginOptions) AddFlags(cmd *cobra.Command) {
	lo.ServerOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(&lo.ClientID, "client-id", "", "OAuth client ID (env: DEADROP_CLIENT_ID)")
	cmd.PersistentFlags().StringVar(&lo.ClientSecret, "client-secret", "", "OAuth client secret (env: DEADROP_CLIENT_SECRET)")
	cmd.PersistentFlags().StringVar(&lo.Provider, "provider", defaultLoginOptions.Provider, "OAuth provider (google)")
	cmd.PersistentFlags().BoolVar(&lo.PrintToken, "print", defaultLoginOptions.PrintToken, "Print the token to stdout")
	cmd.PersistentFlags().BoolVar(&lo.Force, "force", false, "Force new login (ignore cached token)")
}

func (lo *LoginOptions) Config() *command.OptionsSetConfig {
	return nil
}

func AddLogin(parent *cobra.Command) {
	opts := defaultLoginOptions

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to obtain a Carabiner identity token",
		Long: `Authenticates with an identity provider and exchanges the token for a Carabiner identity.

This command will:
1. Check for a cached valid identity token for the server (unless --force is used)
2. If no valid token exists, open a browser for OAuth authentication
3. Exchange the IdP token with the deadrop server for a Carabiner identity token
4. Save the identity token to a server-specific session directory

Sessions are stored in ~/.config/carabiner/<session-id>/identity.json with a
sessions.json file tracking which session belongs to which server.

Examples:
  # Login with Google (default)
  deadrop login

  # Login to a specific server
  deadrop login --server https://auth.carabiner.dev

  # Force new login (ignore cached token)
  deadrop login --force

  # Print token to stdout
  deadrop login --print`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// Load configuration first to get server URL
			cfg, err := config.LoadWithDefaults()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// Apply flag overrides
			if opts.ClientID != "" {
				cfg.ClientID = opts.ClientID
			}
			if opts.ClientSecret != "" {
				cfg.ClientSecret = opts.ClientSecret
			}
			if opts.Server != "" {
				cfg.ServerURL = opts.Server
			}
			if opts.Provider != "" {
				cfg.Provider = opts.Provider
			}

			// Validate configuration
			if err := cfg.Validate(); err != nil {
				return err
			}

			// Check for cached identity token for this server (unless --force)
			if !opts.Force {
				if token, exp, err := loadCachedIdentityForServer(ctx, cfg.ServerURL); err == nil {
					timeUntil := time.Until(exp)
					fmt.Fprintf(os.Stderr, "Using cached identity for %s (expires in %v)\n", cfg.ServerURL, timeUntil.Round(time.Second))
					if opts.PrintToken {
						fmt.Println(token)
					}
					return nil
				}
			}

			// OAuth login flow
			fmt.Fprintf(os.Stderr, "Starting %s login...\n", cfg.Provider)

			oauthFlow := &oauth.OAuthFlow{
				ClientID:     cfg.ClientID,
				ClientSecret: cfg.ClientSecret,
				AuthURL:      cfg.GetAuthURL(),
				TokenURL:     cfg.GetTokenURL(),
				IssuerURL:    cfg.GetIssuerURL(),
				Scopes:       cfg.GetScopes(),
			}

			loginResult, err := oauthFlow.Login(ctx)
			if err != nil {
				return fmt.Errorf("login failed: %w", err)
			}

			fmt.Fprintln(os.Stderr, "Authentication successful")

			// Exchange IdP token for Carabiner identity token
			fmt.Fprintln(os.Stderr, "Obtaining Carabiner identity...")

			exchangeClient := exchange.NewClient(cfg.ServerURL)
			exchangeReq := &exchange.ExchangeRequest{
				SubjectToken:       loginResult.IDToken,
				SubjectTokenType:   exchange.TokenTypeJWT,
				RequestedTokenType: exchange.TokenTypeJWT,
				Audience:           []string{CarabinerAudience},
			}

			exchangeResp, err := exchangeClient.ExchangeToken(ctx, exchangeReq)
			if err != nil {
				return fmt.Errorf("failed to obtain identity: %w", err)
			}

			// Save identity token to session
			if err := saveSessionIdentity(cfg.ServerURL, exchangeResp.AccessToken); err != nil {
				return fmt.Errorf("failed to save identity: %w", err)
			}

			identityPath, _ := getSessionIdentityPath(cfg.ServerURL)
			fmt.Fprintf(os.Stderr, "Identity saved to %s\n", identityPath)

			if opts.PrintToken {
				fmt.Println(exchangeResp.AccessToken)
			}

			return nil
		},
	}
	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}

// saveSessionIdentity saves the token to the session-specific identity file for a server.
func saveSessionIdentity(serverURL, token string) error {
	// Get or create session for this server
	_, err := getOrCreateSession(serverURL)
	if err != nil {
		return fmt.Errorf("getting session: %w", err)
	}

	identityPath, err := getSessionIdentityPath(serverURL)
	if err != nil {
		return err
	}

	// Ensure the directory exists
	identityDir := filepath.Dir(identityPath)
	if err := os.MkdirAll(identityDir, 0700); err != nil {
		return fmt.Errorf("creating session directory: %w", err)
	}

	// Write token atomically
	tempPath := identityPath + ".tmp"
	if err := os.WriteFile(tempPath, []byte(token+"\n"), 0600); err != nil {
		return fmt.Errorf("writing identity file: %w", err)
	}

	if err := os.Rename(tempPath, identityPath); err != nil {
		os.Remove(tempPath) //nolint:errcheck
		return fmt.Errorf("renaming identity file: %w", err)
	}

	return nil
}

// loadCachedIdentityForServer loads and validates the cached identity token for a specific server.
func loadCachedIdentityForServer(ctx context.Context, serverURL string) (string, time.Time, error) {
	identityPath, err := getSessionIdentityPath(serverURL)
	if err != nil {
		return "", time.Time{}, err
	}

	data, err := os.ReadFile(identityPath)
	if err != nil {
		return "", time.Time{}, err
	}

	token := strings.TrimSpace(string(data))

	if token == "" {
		return "", time.Time{}, errors.New("identity file is empty")
	}

	// Extract and validate expiry
	exp, err := extractTokenExpiry(token)
	if err != nil {
		return "", time.Time{}, err
	}

	if time.Now().After(exp) {
		return "", time.Time{}, errors.New("cached token is expired")
	}

	return token, exp, nil
}

// getCarabinerIdentityPath returns the path to the default carabiner identity file.
// This uses the default session if one exists.
func getCarabinerIdentityPath() (string, error) {
	// Try to get the default session's identity path
	identityPath, err := getDefaultIdentityPath()
	if err == nil {
		return identityPath, nil
	}

	// Fallback to legacy path for backwards compatibility
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("getting user config directory: %w", err)
	}
	return filepath.Join(configDir, credentials.DefaultConfigDir, credentials.DefaultCredentialsFile), nil
}

// extractTokenExpiry extracts the expiry time from a JWT token.
func extractTokenExpiry(token string) (time.Time, error) {
	parts := splitJWT(token)
	if len(parts) != 3 {
		return time.Time{}, errors.New("invalid JWT format")
	}

	// Decode the payload (second part)
	payload, err := base64DecodeSegment(parts[1])
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

// splitJWT splits a JWT into its parts.
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

// base64DecodeSegment decodes a base64url encoded segment.
func base64DecodeSegment(seg string) ([]byte, error) {
	// Add padding if needed
	switch len(seg) % 4 {
	case 2:
		seg += "=="
	case 3:
		seg += "="
	}

	return base64.URLEncoding.DecodeString(seg)
}
