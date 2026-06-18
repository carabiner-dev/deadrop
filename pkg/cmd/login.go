// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/deadrop/pkg/client/config"
	"github.com/carabiner-dev/deadrop/pkg/client/credentials"
)

var _ command.OptionsSet = (*LoginOptions)(nil)

type LoginOptions struct {
	ServerOptions
	LoginOpts
}

var defaultLoginOptions = LoginOptions{
	ServerOptions: defaultServerOptions,
	LoginOpts:     defaultLoginOpts,
}

// Validate the options set
func (lo *LoginOptions) Validate() error {
	errs := []error{
		lo.ServerOptions.Validate(),
		lo.LoginOpts.Validate(),
	}
	return errors.Join(errs...)
}

func (lo *LoginOptions) AddFlags(cmd *cobra.Command) {
	lo.ServerOptions.AddFlags(cmd)
	lo.LoginOpts.AddFlags(cmd)
}

func (lo *LoginOptions) Config() *command.OptionsSetConfig {
	return nil
}

func AddLogin(parent *cobra.Command) {
	opts := defaultLoginOptions

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to obtain a Carabiner identity token",
		Long: `Authenticates and obtains a Carabiner identity token.

This command will:
1. Check for a cached valid identity token for the server (unless --force is used)
2. Probe for ambient credentials (e.g. GitHub Actions or GitLab CI OIDC
   tokens) and exchange them at the deadrop server for a Carabiner identity
3. If no ambient credentials exist, open a browser to authenticate with an
   identity provider via the Carabiner login service
4. Save the identity token to a server-specific session directory

Sessions are stored in ~/.config/carabiner/<session-id>/identity.json with a
sessions.json file tracking which session belongs to which server.

Examples:
  # Login with Google (default)
  carabiner login

  # Login to a specific server
  carabiner login --auth-server https://auth.carabiner.dev

  # Force new login (ignore cached token)
  carabiner login --force

  # Print token to stdout
  carabiner login --print`,
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
			if opts.Server != "" {
				cfg.ServerURL = opts.Server
			}
			if opts.LoginURL != "" {
				cfg.LoginURL = opts.LoginURL
			}

			// For login, we need the server URL to be set
			if cfg.ServerURL == "" {
				return fmt.Errorf("server URL is required (set via --auth-server flag or DEADROP_SERVER env var)")
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

			// Log in: ambient credentials first, browser flow as the
			// interactive fallback.
			token, err := credentials.Login(ctx, cfg.ServerURL, cfg.LoginURL)
			if err != nil {
				return err
			}

			// Save the token
			if err := credentials.SaveIdentity(cfg.ServerURL, token); err != nil {
				return fmt.Errorf("saving identity: %w", err)
			}

			identityPath, _ := credentials.GetSessionIdentityPath(cfg.ServerURL) //nolint:errcheck // path is informational only
			fmt.Fprintf(os.Stderr, "Authentication successful!\n")
			fmt.Fprintf(os.Stderr, "Identity saved to %s\n", identityPath)

			if opts.PrintToken {
				fmt.Println(token)
			}

			return nil
		},
	}
	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
