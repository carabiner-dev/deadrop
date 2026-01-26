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

	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*ExchangeOptions)(nil)

// ExchangeOptions are the options to perform a token exchange
type ExchangeOptions struct {
	TokenReadOptions
	ServerOptions
	Audience []string
	Scope    []string
	Resource []string
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
}

func (eo *ExchangeOptions) Config() *command.OptionsSetConfig {
	return nil
}

func AddExchange(parent *cobra.Command) {
	opts := defaultExchangeOptions

	cmd := &cobra.Command{
		Use:   "exchange <token-file>",
		Short: "Exchange a JWT token via the deadropx server",
		Long: `Exchange a JWT token for a new token from the deadropx server.

The token is read from a file path. Use "-" to read from stdin.

Examples:
  # Exchange a token from a file
  deadrop exchange token.jwt --audience https://api.example.com

  # Read token from stdin
  echo "$TOKEN" | deadrop exchange - --audience https://api.example.com

  # Exchange with multiple audiences and resources
  deadrop exchange token.jwt \
    --audience https://api.example.com \
    --audience https://api.staging.example.com \
    --resource https://api.example.com/users

  # Use a custom exchange server
  deadrop exchange token.jwt --server https://auth.mycompany.com --audience https://api.example.com`,
		Args: cobra.MaximumNArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if opts.TokenPath == "" && len(args) > 0 && args[0] != "" {
				opts.TokenPath = args[0]
			}
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Read token from file or stdin
			token, err := opts.ReadToken()
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
			resp, err := client.ExchangeToken(cmd.Context(), req)
			if err != nil {
				return fmt.Errorf("token exchange failed: %w", err)
			}

			// Print metadata to stderr
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "Token Type:  %s\n", resp.TokenType)
			fmt.Fprintf(os.Stderr, "Issued Type: %s\n", resp.IssuedTokenType)
			fmt.Fprintf(os.Stderr, "Expires In:  %s\n", time.Duration(resp.ExpiresIn)*time.Second)
			fmt.Fprintln(os.Stderr)

			// Decode and show JWT claims
			if err := decodeJWT(resp.AccessToken); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to decode JWT: %v\n", err)
			}
			fmt.Fprintln(os.Stderr)

			// Print token to stdout
			fmt.Println(resp.AccessToken)

			return nil
		},
	}
	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
