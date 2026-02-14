// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/deadrop/pkg/client/config"
	"github.com/carabiner-dev/deadrop/pkg/client/credentials"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*WhoamiOptions)(nil)

type WhoamiOptions struct {
	ServerOptions
	JSON bool
}

var defaultWhoamiOptions = WhoamiOptions{}

func (wo *WhoamiOptions) Validate() error {
	return wo.ServerOptions.Validate()
}

func (wo *WhoamiOptions) AddFlags(cmd *cobra.Command) {
	wo.ServerOptions.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(&wo.JSON, "json", false, "Output in JSON format")
}

func (wo *WhoamiOptions) Config() *command.OptionsSetConfig {
	return nil
}

// TokenClaims represents the claims we extract from the Carabiner token
type TokenClaims struct {
	Subject   string   `json:"sub,omitempty"`
	Email     string   `json:"email,omitempty"`
	Name      string   `json:"name,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	Provider  string   `json:"provider,omitempty"`
}

func AddWhoami(parent *cobra.Command) {
	opts := defaultWhoamiOptions

	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Display the current authenticated identity",
		Long: `Displays information about the currently authenticated Carabiner identity.

This command reads the stored identity token for the configured server and
displays the identity claims (subject, email, expiration, etc.).

Examples:
  # Show current identity
  carabiner whoami

  # Show identity for a specific server
  carabiner whoami --server https://auth.carabiner.dev

  # Output as JSON
  carabiner whoami --json`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
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

			// Load the identity token
			token, exp, err := credentials.LoadIdentity(serverURL)
			if err != nil {
				return fmt.Errorf("no identity found for %s (run 'carabiner login' first): %w", serverURL, err)
			}

			// Parse the token claims using golang-jwt
			claims, err := parseTokenClaims(token)
			if err != nil {
				return fmt.Errorf("parsing token: %w", err)
			}

			// Output
			if opts.JSON {
				output := struct {
					Server    string       `json:"server"`
					Claims    *TokenClaims `json:"claims"`
					ExpiresIn string       `json:"expires_in"`
				}{
					Server:    serverURL,
					Claims:    claims,
					ExpiresIn: time.Until(exp).Round(time.Second).String(),
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(output)
			}

			// Human-readable output
			fmt.Printf("Server:     %s\n", serverURL)
			if claims.Subject != "" {
				fmt.Printf("Subject:    %s\n", claims.Subject)
			}
			if claims.Email != "" {
				fmt.Printf("Email:      %s\n", claims.Email)
			}
			if claims.Name != "" {
				fmt.Printf("Name:       %s\n", claims.Name)
			}
			if claims.Issuer != "" {
				fmt.Printf("Issuer:     %s\n", claims.Issuer)
			}
			if len(claims.Audience) > 0 {
				fmt.Printf("Audience:   %s\n", strings.Join(claims.Audience, ", "))
			}
			if claims.Provider != "" {
				fmt.Printf("Provider:   %s\n", claims.Provider)
			}
			fmt.Printf("Expires:    %s (in %s)\n", exp.Format(time.RFC3339), time.Until(exp).Round(time.Second))

			return nil
		},
	}
	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}

// carabinerClaims extends jwt.RegisteredClaims with custom Carabiner claims
type carabinerClaims struct {
	jwt.RegisteredClaims
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
	Provider string `json:"provider,omitempty"`
}

// parseTokenClaims extracts claims from a JWT token without signature validation.
func parseTokenClaims(tokenString string) (*TokenClaims, error) {
	// Parse without validation (we just want to read the claims)
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, &carabinerClaims{})
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %w", err)
	}

	claims, ok := token.Claims.(*carabinerClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	// Convert to our TokenClaims struct
	result := &TokenClaims{
		Subject:  claims.Subject,
		Email:    claims.Email,
		Name:     claims.Name,
		Issuer:   claims.Issuer,
		Provider: claims.Provider,
	}

	// Handle audience (jwt.ClaimStrings handles both string and []string)
	if claims.Audience != nil {
		result.Audience = claims.Audience
	}

	// Handle timestamps
	if claims.ExpiresAt != nil {
		result.ExpiresAt = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		result.IssuedAt = claims.IssuedAt.Unix()
	}

	return result, nil
}
