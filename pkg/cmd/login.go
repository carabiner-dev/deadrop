// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/carabiner-dev/deadrop/pkg/client/config"
	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
	"github.com/carabiner-dev/deadrop/pkg/client/github"
	"github.com/carabiner-dev/deadrop/pkg/client/oauth"
	"github.com/carabiner-dev/deadrop/pkg/client/storage"
	"github.com/spf13/cobra"
)

func newLoginCmd() *cobra.Command {
	var (
		clientID      string
		clientSecret  string
		serverURL     string
		provider      string
		audience      []string
		save          bool
		printToken    bool
		force         bool
		githubActions bool
	)

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to a carabiner deadrop server",
		Long: `Logs into an identity provider and exchanges its token for a carabiner deadrop token.

This command will:
1. Check for a cached valid token (unless --force is used)
2. If no valid token exists, open a browser for OAuth authentication
3. Exchange the OAuth token with the deadrop server
4. Save the Carabiner Deadrop token to disk (unless --save is false)
5. Print the Carabiner Deadrop token to stdout (unless --print is false)

Examples:
  # Login with environment variables
  export DEADROP_CLIENT_ID="123456.apps.googleusercontent.com"
  export DEADROP_SERVER="https://auth.carabiner.dev"
  deadrop login --audience my-service

  # Login with flags
  deadrop login \
    --client-id "123456.apps.googleusercontent.com" \
    --server "https://auth.carabiner.dev" \
    --audience my-service

  # Force new login (ignore cache)
  deadrop login --force

  # Login from GitHub Actions
  deadrop login --github-actions --audience my-service`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogin(cmd, clientID, clientSecret, serverURL, provider, audience, save, printToken, force, githubActions)
		},
	}

	// Flags
	cmd.Flags().StringVar(&clientID, "client-id", "", "OAuth client ID (env: DEADROP_CLIENT_ID)")
	cmd.Flags().StringVar(&clientSecret, "client-secret", "", "OAuth client secret (env: DEADROP_CLIENT_SECRET)")
	cmd.Flags().StringVar(&serverURL, "server", "", "Deadrop server URL (env: DEADROP_SERVER)")
	cmd.Flags().StringVar(&provider, "provider", "google", "OAuth provider (google, microsoft, github)")
	cmd.Flags().StringSliceVar(&audience, "audience", []string{}, "Target audience(s)")
	cmd.Flags().BoolVar(&save, "save", true, "Save token to disk")
	cmd.Flags().BoolVar(&printToken, "print", true, "Print the deadrop token to stdout")
	cmd.Flags().BoolVar(&force, "force", false, "Force new login (ignore cached token)")
	cmd.Flags().BoolVar(&githubActions, "github-actions", false, "Use GitHub Actions OIDC token")

	return cmd
}

func runLogin(cmd *cobra.Command, clientID, clientSecret, serverURL, provider string, audience []string, save, printToken, force, githubActions bool) error {
	ctx := cmd.Context()

	// Load configuration
	cfg, err := config.LoadWithDefaults()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Apply flag overrides
	if clientID != "" {
		cfg.ClientID = clientID
	}
	if clientSecret != "" {
		cfg.ClientSecret = clientSecret
	}
	if serverURL != "" {
		cfg.ServerURL = serverURL
	}
	if provider != "" {
		cfg.Provider = provider
	}
	if len(audience) > 0 {
		cfg.Audience = audience
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Initialize token storage
	store, err := storage.NewTokenStorage()
	if err != nil {
		return fmt.Errorf("initializing token storage: %w", err)
	}

	// Check for cached token (unless --force)
	if !force {
		cached, err := store.LoadToken(ctx)
		if err == nil && cached.IsValid() {
			timeUntil := cached.TimeUntilExpiry()
			fmt.Fprintf(os.Stderr, "✓ Using cached token (expires in %v)\n", timeUntil.Round(time.Second))

			if printToken {
				fmt.Println(cached.Token)
			}
			return nil
		}
	}

	// Get identity provider token (GitHub Actions or OAuth)
	var idToken string

	if githubActions || github.IsGitHubActions() {
		// GitHub Actions token retrieval
		fmt.Fprintln(os.Stderr, "Retrieving GitHub Actions OIDC token...")

		retriever, err := github.NewActionsTokenRetriever(
			func() string {
				if len(cfg.Audience) > 0 {
					return cfg.Audience[0]
				}
				return ""
			}(),
		)
		if err != nil {
			return fmt.Errorf("initializing GitHub Actions token retriever: %w", err)
		}

		idToken, err = retriever.GetToken(ctx)
		if err != nil {
			return fmt.Errorf("retrieving GitHub Actions token: %w", err)
		}

		fmt.Fprintln(os.Stderr, "✓ GitHub Actions token retrieved")
	} else {
		// OAuth login flow
		fmt.Fprintln(os.Stderr, "Starting OAuth login...")

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
			return fmt.Errorf("OAuth login failed: %w", err)
		}

		idToken = loginResult.IDToken
		fmt.Fprintln(os.Stderr, "✓ OAuth login successful")
	}

	// Exchange token with deadrop server
	fmt.Fprintln(os.Stderr, "Exchanging token with deadrop server...")

	exchangeClient := exchange.NewClient(cfg.ServerURL)
	exchangeReq := &exchange.ExchangeRequest{
		SubjectToken:       idToken,
		SubjectTokenType:   exchange.TokenTypeJWT,
		RequestedTokenType: exchange.TokenTypeJWT,
		Audience:           cfg.Audience,
	}

	exchangeResp, err := exchangeClient.ExchangeToken(ctx, exchangeReq)
	if err != nil {
		return fmt.Errorf("error logging in: %w", err)
	}

	fmt.Fprintln(os.Stderr, "✓ Token exchanged successfully")

	// Save to disk (unless --no-save)
	if save {
		// Determine provider for storage
		providerName := cfg.Provider
		if githubActions || github.IsGitHubActions() {
			providerName = "github"
		}

		storedToken := &storage.StoredToken{
			Token:         exchangeResp.AccessToken,
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(time.Duration(exchangeResp.ExpiresIn) * time.Second),
			Provider:      providerName,
			ServerURL:     cfg.ServerURL,
			OriginalToken: idToken,
		}

		if err := store.SaveToken(ctx, storedToken); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save token: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "✓ Token saved to %s\n", store.DataDir)
		}
	}

	// Print to stdout (unless --no-print)
	if printToken {
		fmt.Println(exchangeResp.AccessToken)
	}

	return nil
}
