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
				if token, exp, err := credentials.LoadIdentity(cfg.ServerURL); err == nil {
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
			if err := credentials.SaveIdentity(cfg.ServerURL, exchangeResp.AccessToken); err != nil {
				return fmt.Errorf("failed to save identity: %w", err)
			}

			identityPath, _ := credentials.GetSessionIdentityPath(cfg.ServerURL)
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
