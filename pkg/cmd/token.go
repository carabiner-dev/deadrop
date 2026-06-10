// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/carabiner-dev/command"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/deadrop/pkg/client/config"
	"github.com/carabiner-dev/deadrop/pkg/client/credentials"
	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
)

var _ command.OptionsSet = (*TokenOptions)(nil)

type TokenOptions struct {
	ServerOptions
	Decode  bool
	Service string // Audience of a cached service token to display
}

var defaultTokenOptions = TokenOptions{}

func (to *TokenOptions) Validate() error {
	return to.ServerOptions.Validate()
}

func (to *TokenOptions) AddFlags(cmd *cobra.Command) {
	to.ServerOptions.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(&to.Decode, "decode", false, "Decode and display JWT claims")
	cmd.PersistentFlags().StringVar(&to.Service, "service", "", "Display a cached service token for this audience instead of the identity token")
}

func (to *TokenOptions) Config() *command.OptionsSetConfig {
	return nil
}

func AddToken(parent *cobra.Command) {
	opts := defaultTokenOptions

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Display the cached identity or service token",
		Long: `Display the cached Carabiner identity token for the configured server.

Use --decode to show the JWT claims in human-readable format.
Use --service to display a cached service token for a specific audience.

Examples:
  # Show identity token for default server
  carabiner token

  # Show token for a specific server
  carabiner token --server https://auth.carabiner.dev

  # Decode and display JWT claims
  carabiner token --decode

  # Show a cached service token for an audience
  carabiner token --service https://api.example.com

  # Show and decode a service token
  carabiner token --service https://api.example.com --decode`,
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

			var token string
			var exp time.Time
			var tokenType string

			if opts.Service != "" {
				// Load a cached service token
				tokenType = "Service"
				req := &exchange.ExchangeRequest{
					Audience: []string{opts.Service},
				}
				token, exp, err = credentials.LoadExchangedToken(serverURL, req)
				if err != nil {
					return fmt.Errorf("no cached service token found for audience %q (use 'carabiner exchange --cache --audience %s' to create one)", opts.Service, opts.Service)
				}
			} else {
				// Load the identity token with auto-renewal
				tokenType = "Identity"
				var renewed bool
				token, exp, renewed, err = credentials.LoadIdentityWithRenewal(ctx, serverURL)
				if err != nil {
					if errors.Is(err, credentials.ErrTokenExpired) {
						return fmt.Errorf("identity token has expired, please run 'carabiner login' to authenticate again")
					}
					return fmt.Errorf("no identity found for %s (run 'carabiner login' first): %w", serverURL, err)
				}

				if renewed {
					fmt.Fprintf(os.Stderr, "Token was automatically renewed\n")
				}
			}

			// Check if token is close to expiring
			timeUntil := time.Until(exp)
			if timeUntil < 5*time.Minute {
				fmt.Fprintf(os.Stderr, "Warning: Token expires soon (in %s)\n", timeUntil.Round(time.Second))
				if opts.Service == "" {
					fmt.Fprintln(os.Stderr, "Run 'carabiner login --force' to get a new token")
				} else {
					fmt.Fprintf(os.Stderr, "Run 'carabiner exchange --cache --audience %s' to refresh\n", opts.Service)
				}
				fmt.Fprintln(os.Stderr)
			}

			// Print info to stderr
			fmt.Fprintf(os.Stderr, "Type:       %s\n", tokenType)
			fmt.Fprintf(os.Stderr, "Server:     %s\n", serverURL)
			if opts.Service != "" {
				fmt.Fprintf(os.Stderr, "Audience:   %s\n", opts.Service)
			}
			fmt.Fprintf(os.Stderr, "Expires:    %s (in %s)\n", exp.Format(time.RFC3339), timeUntil.Round(time.Second))

			// Decode JWT if requested
			if opts.Decode {
				fmt.Fprintln(os.Stderr)
				if opts.Service != "" {
					// For service tokens, show all claims
					if err := printAllClaims(token); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to decode JWT: %v\n", err)
					}
				} else {
					// For identity tokens, show standard claims
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

// printAllClaims decodes and prints all claims from a JWT token.
func printAllClaims(token string) error {
	parser := jwt.NewParser()
	parsed, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("parsing JWT: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid claims type")
	}

	fmt.Fprintln(os.Stderr, "JWT Claims:")

	// Sort keys for consistent output
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := claims[k]
		// Format the value nicely
		switch val := v.(type) {
		case string:
			fmt.Fprintf(os.Stderr, "  %s: %s\n", k, val)
		case float64:
			// Check if it's a timestamp (common for iat, exp, nbf)
			if k == "iat" || k == "exp" || k == "nbf" {
				t := time.Unix(int64(val), 0)
				fmt.Fprintf(os.Stderr, "  %s: %s (%d)\n", k, t.Format(time.RFC3339), int64(val))
			} else {
				fmt.Fprintf(os.Stderr, "  %s: %v\n", k, val)
			}
		case []interface{}:
			// Format arrays nicely
			strs := make([]string, len(val))
			for i, item := range val {
				strs[i] = fmt.Sprintf("%v", item)
			}
			jsonBytes, _ := json.Marshal(strs) //nolint:errcheck,errchkjson // display only
			fmt.Fprintf(os.Stderr, "  %s: %s\n", k, string(jsonBytes))
		default:
			jsonBytes, _ := json.Marshal(val) //nolint:errcheck,errchkjson // display only
			fmt.Fprintf(os.Stderr, "  %s: %s\n", k, string(jsonBytes))
		}
	}

	return nil
}
