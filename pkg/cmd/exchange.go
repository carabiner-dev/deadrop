// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/deadrop/pkg/client/credentials"
	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
)

var _ command.OptionsSet = (*ExchangeOptions)(nil)

// ExchangeOptions are the options to perform a token exchange
type ExchangeOptions struct {
	TokenReadOptions
	ServerOptions
	Audience []string
	Scope    []string
	Resource []string
	Cache    bool // Enable token caching
}

var defaultExchangeOptions = ExchangeOptions{
	TokenReadOptions: defaultTokenReadOptions,
	ServerOptions:    defaultServerOptions,
}

func (eo *ExchangeOptions) Validate() error {
	errs := []error{
		eo.TokenReadOptions.Validate(),
		eo.ServerOptions.Validate(),
	}
	if eo.Server == "" {
		errs = append(errs, errors.New("exchange server is not defined"))
	}

	if len(eo.Audience) == 0 {
		errs = append(errs, errors.New("at least one --audience is required"))
	}

	return errors.Join(errs...)
}

func (eo *ExchangeOptions) AddFlags(cmd *cobra.Command) {
	eo.TokenReadOptions.AddFlags(cmd)
	eo.ServerOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringSliceVar(&eo.Audience, "audience", nil, "Target audience(s)")
	cmd.PersistentFlags().StringSliceVar(&eo.Scope, "scope", nil, "Requested scope(s)")
	cmd.PersistentFlags().StringSliceVar(&eo.Resource, "resource", nil, "Resource URI(s)")
	cmd.PersistentFlags().BoolVar(&eo.Cache, "cache", false, "Cache exchanged tokens locally for reuse")
}

func (eo *ExchangeOptions) Config() *command.OptionsSetConfig {
	return nil
}

func AddExchange(parent *cobra.Command) {
	opts := defaultExchangeOptions

	cmd := &cobra.Command{
		Use:   "exchange",
		Short: "Exchange your Carabiner identity for a service token",
		Long: `Exchange your Carabiner identity token for a new token with a specific audience.

By default, the command uses your Carabiner identity from ~/.config/carabiner/identity.json
(created by 'deadrop login'). You can also pipe a token or specify one with --token.

Token source precedence:
  1. Piped input (stdin)
  2. --token flag (explicit file path)
  3. Carabiner identity file (default)

Examples:
  # Exchange using your Carabiner identity (default)
  deadrop exchange --audience https://api.example.com

  # Exchange with multiple audiences
  deadrop exchange \
    --audience https://api.example.com \
    --audience https://api.staging.example.com

  # Pipe a token
  echo "$TOKEN" | deadrop exchange --audience https://api.example.com

  # Use a specific token file
  deadrop exchange --token /path/to/token.jwt --audience https://api.example.com

  # Use a custom exchange server
  deadrop exchange --auth-server https://auth.mycompany.com --audience https://api.example.com

  # Use caching (reuses token if still valid)
  deadrop exchange --audience https://api.example.com --cache`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			var accessToken string
			var expiresIn time.Duration
			var fromCache bool

			// If caching is enabled and no explicit token source, use the credentials cache
			if opts.Cache && opts.TokenPath == "" && !hasStdinData() {
				req := &exchange.ExchangeRequest{
					Audience: opts.Audience,
					Scope:    opts.Scope,
					Resource: opts.Resource,
				}

				token, exp, exchanged, err := credentials.LoadExchangedTokenWithRenewal(ctx, opts.Server, req)
				if err != nil {
					return fmt.Errorf("getting cached token: %w", err)
				}

				accessToken = token
				expiresIn = time.Until(exp)
				fromCache = !exchanged

				if fromCache {
					fmt.Fprintf(os.Stderr, "Using cached token (expires in %s)\n", expiresIn.Round(time.Second))
				} else {
					fmt.Fprintf(os.Stderr, "Exchanged and cached new token (expires in %s)\n", expiresIn.Round(time.Second))
				}
			} else {
				// Read token from file or stdin (with auto-renewal for carabiner identity)
				token, err := opts.ReadTokenWithContext(ctx)
				if err != nil {
					return fmt.Errorf("reading token: %w", err)
				}

				// Basic JWT format validation
				parts := strings.Split(token, ".")
				if len(parts) != 3 {
					return fmt.Errorf("invalid JWT format: expected 3 parts separated by '.', got %d parts (token length: %d chars)", len(parts), len(token))
				}

				// Create exchange client
				client := exchange.NewClient(opts.Server)

				// Build request
				req := &exchange.ExchangeRequest{
					SubjectToken: token,
					Audience:     opts.Audience,
					Scope:        opts.Scope,
					Resource:     opts.Resource,
				}

				// Perform exchange
				fmt.Fprintf(os.Stderr, "Exchanging token with %s...\n", opts.Server)
				resp, err := client.ExchangeToken(ctx, req)
				if err != nil {
					return fmt.Errorf("token exchange failed: %w", err)
				}

				accessToken = resp.AccessToken
				expiresIn = time.Duration(resp.ExpiresIn) * time.Second

				// Print metadata to stderr
				fmt.Fprintln(os.Stderr)
				fmt.Fprintf(os.Stderr, "Token Type:  %s\n", resp.TokenType)
				fmt.Fprintf(os.Stderr, "Issued Type: %s\n", resp.IssuedTokenType)
				fmt.Fprintf(os.Stderr, "Expires In:  %s\n", expiresIn)
				fmt.Fprintln(os.Stderr)
			}

			// Decode and show JWT claims
			claims, err := parseTokenClaims(accessToken)
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
				if len(claims.Audience) > 0 {
					fmt.Fprintf(os.Stderr, "  Audience: %s\n", strings.Join(claims.Audience, ", "))
				}
			}
			fmt.Fprintln(os.Stderr)

			// Print token to stdout
			fmt.Println(accessToken)

			return nil
		},
	}
	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
