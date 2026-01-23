// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/deadrop/pkg/client/config"
	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
	"github.com/carabiner-dev/deadrop/pkg/client/github"
	"github.com/carabiner-dev/deadrop/pkg/client/oauth"
	"github.com/carabiner-dev/deadrop/pkg/client/storage"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*LoginOptions)(nil)

type LoginOptions struct {
	ServerOptions
	ClientID      string
	ClientSecret  string
	Provider      string
	Audience      []string
	Save          bool
	PrintToken    bool
	Force         bool
	GitHubActions bool
}

var defaultLoginOptions = LoginOptions{
	Provider:   "google",
	Save:       true,
	PrintToken: true,
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
	cmd.PersistentFlags().StringVar(&lo.Provider, "provider", defaultLoginOptions.Provider, "OAuth provider (google, microsoft, github)")
	cmd.PersistentFlags().StringSliceVar(&lo.Audience, "audience", []string{}, "Target audience(s)")
	cmd.PersistentFlags().BoolVar(&lo.Save, "save", defaultLoginOptions.Save, "Save token to disk")
	cmd.PersistentFlags().BoolVar(&lo.PrintToken, "print", defaultLoginOptions.PrintToken, "Print the deadrop token to stdout")
	cmd.PersistentFlags().BoolVar(&lo.Force, "force", false, "Force new login (ignore cached token)")
	cmd.PersistentFlags().BoolVar(&lo.GitHubActions, "github-actions", false, "Use GitHub Actions OIDC token")
}

func (lo *LoginOptions) Config() *command.OptionsSetConfig {
	return nil
}

func AddLogin(parent *cobra.Command) {
	opts := defaultLoginOptions

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
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// Load configuration
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
			if len(opts.Audience) > 0 {
				cfg.Audience = opts.Audience
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
			if !opts.Force {
				cached, err := store.LoadToken(ctx)
				if err == nil && cached.IsValid() {
					timeUntil := cached.TimeUntilExpiry()
					fmt.Fprintf(os.Stderr, "✓ Using cached token (expires in %v)\n", timeUntil.Round(time.Second))

					if opts.PrintToken {
						fmt.Println(cached.Token)
					}
					return nil
				}
			}

			// Get identity provider token (GitHub Actions or OAuth)
			var idToken string

			if opts.GitHubActions || github.IsGitHubActions() {
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
			if opts.Save {
				// Determine provider for storage
				providerName := cfg.Provider
				if opts.GitHubActions || github.IsGitHubActions() {
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
			if opts.PrintToken {
				fmt.Println(exchangeResp.AccessToken)
			}

			return nil
		},
	}
	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
