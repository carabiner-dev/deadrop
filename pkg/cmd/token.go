// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/deadrop/pkg/client/storage"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*TokenOptions)(nil)

type TokenOptions struct {
	Decode bool
}

var defaultTokenOptions = TokenOptions{}

func (to *TokenOptions) Validate() error {
	return nil
}

func (to *TokenOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&to.Decode, "decode", false, "Decode and display JWT claims")
}

func (to *TokenOptions) Config() *command.OptionsSetConfig {
	return nil
}

func AddToken(parent *cobra.Command) {
	opts := defaultTokenOptions

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Display cached token",
		Long: `Display the cached Carabiner token.

Use --decode to show the JWT claims in human-readable format.`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// Load token from storage
			store, err := storage.NewTokenStorage()
			if err != nil {
				return fmt.Errorf("initializing token storage: %w", err)
			}

			cached, err := store.LoadToken(ctx)
			if err != nil {
				return fmt.Errorf("no cached token found. Run 'deadrop login' first")
			}

			// Check if token is expired
			if !cached.IsValid() {
				fmt.Fprintf(os.Stderr, "Warning: Token is expired (expired %v ago)\n",
					time.Since(cached.ExpiresAt).Round(time.Second))
				fmt.Fprintln(os.Stderr, "Run 'deadrop login --force' to get a new token")
				fmt.Println()
			}

			// Print basic info
			fmt.Fprintf(os.Stderr, "Provider:   %s\n", cached.Provider)
			fmt.Fprintf(os.Stderr, "Server:     %s\n", cached.ServerURL)
			fmt.Fprintf(os.Stderr, "Issued:     %s\n", cached.IssuedAt.Format(time.RFC3339))
			fmt.Fprintf(os.Stderr, "Expires:    %s\n", cached.ExpiresAt.Format(time.RFC3339))
			if cached.IsValid() {
				fmt.Fprintf(os.Stderr, "Valid for:  %v\n", cached.TimeUntilExpiry().Round(time.Second))
			}
			fmt.Fprintln(os.Stderr)

			// Decode JWT if requested
			if opts.Decode {
				if err := decodeJWT(cached.Token); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to decode JWT: %v\n", err)
				}
				fmt.Fprintln(os.Stderr)
			}

			// Print token
			fmt.Println(cached.Token)

			return nil
		},
	}
	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}

// decodeJWT decodes and prints JWT claims
func decodeJWT(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decoding payload: %w", err)
	}

	// Pretty print JSON
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("parsing claims: %w", err)
	}

	fmt.Fprintln(os.Stderr, "JWT Claims:")
	prettyJSON, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, string(prettyJSON))

	return nil
}
