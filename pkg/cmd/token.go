// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/deadrop/pkg/client/config"
	"github.com/carabiner-dev/deadrop/pkg/client/credentials"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*TokenOptions)(nil)

type TokenOptions struct {
	ServerOptions
	Decode bool
}

var defaultTokenOptions = TokenOptions{}

func (to *TokenOptions) Validate() error {
	return to.ServerOptions.Validate()
}

func (to *TokenOptions) AddFlags(cmd *cobra.Command) {
	to.ServerOptions.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(&to.Decode, "decode", false, "Decode and display JWT claims")
}

func (to *TokenOptions) Config() *command.OptionsSetConfig {
	return nil
}

func AddToken(parent *cobra.Command) {
	opts := defaultTokenOptions

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Display the cached identity token",
		Long: `Display the cached Carabiner identity token for the configured server.

Use --decode to show the JWT claims in human-readable format.

Examples:
  # Show token for default server
  carabiner token

  # Show token for a specific server
  carabiner token --server https://auth.carabiner.dev

  # Decode and display JWT claims
  carabiner token --decode`,
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

			// Determine which server to use
			serverURL := cfg.ServerURL
			if serverURL == "" {
				// Try to get the default session
				_, defaultServer, err := credentials.GetDefaultSession()
				if err != nil {
					return fmt.Errorf("no server configured and no default session found (run 'carabiner login' first)")
				}
				serverURL = defaultServer
			}

			// Load the identity token with auto-renewal
			token, exp, renewed, err := credentials.LoadIdentityWithRenewal(ctx, serverURL)
			if err != nil {
				if err == credentials.ErrTokenExpired {
					return fmt.Errorf("identity token has expired, please run 'carabiner login' to authenticate again")
				}
				return fmt.Errorf("no identity found for %s (run 'carabiner login' first): %w", serverURL, err)
			}

			if renewed {
				fmt.Fprintf(os.Stderr, "Token was automatically renewed\n")
			}

			// Check if token is close to expiring
			timeUntil := time.Until(exp)
			if timeUntil < 5*time.Minute {
				fmt.Fprintf(os.Stderr, "Warning: Token expires soon (in %s)\n", timeUntil.Round(time.Second))
				fmt.Fprintln(os.Stderr, "Run 'carabiner login --force' to get a new token")
				fmt.Fprintln(os.Stderr)
			}

			// Print info to stderr
			fmt.Fprintf(os.Stderr, "Server:     %s\n", serverURL)
			fmt.Fprintf(os.Stderr, "Expires:    %s (in %s)\n", exp.Format(time.RFC3339), timeUntil.Round(time.Second))

			// Decode JWT if requested
			if opts.Decode {
				fmt.Fprintln(os.Stderr)
				claims, err := parseTokenClaims(token)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to decode JWT: %v\n", err)
				} else {
					fmt.Fprintln(os.Stderr, "JWT Claims:")
					if claims.Subject != "" {
						fmt.Fprintf(os.Stderr, "  Subject:  %s\n", claims.Subject)
					}
					if claims.Email != "" {
						fmt.Fprintf(os.Stderr, "  Email:    %s\n", claims.Email)
					}
					if claims.Name != "" {
						fmt.Fprintf(os.Stderr, "  Name:     %s\n", claims.Name)
					}
					if claims.Issuer != "" {
						fmt.Fprintf(os.Stderr, "  Issuer:   %s\n", claims.Issuer)
					}
					if claims.Provider != "" {
						fmt.Fprintf(os.Stderr, "  Provider: %s\n", claims.Provider)
					}
				}
			}

			fmt.Fprintln(os.Stderr)

			// Print token to stdout (for piping)
			fmt.Println(token)

			return nil
		},
	}
	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
