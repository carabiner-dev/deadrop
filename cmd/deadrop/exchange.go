// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
	"github.com/spf13/cobra"
)

const defaultServer = "https://auth.carabiner.dev"

func newExchangeCmd() *cobra.Command {
	var (
		server   string
		audience []string
		scope    []string
		resource []string
	)

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

  # Use a custom server
  deadrop exchange token.jwt --server https://auth.mycompany.com --audience https://api.example.com`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Read token from file or stdin
			token, err := readToken(args[0])
			if err != nil {
				return fmt.Errorf("reading token: %w", err)
			}
			return runExchange(cmd, server, token, audience, scope, resource)
		},
	}

	cmd.Flags().StringVar(&server, "server", defaultServer, "Deadropx server URL")
	cmd.Flags().StringSliceVar(&audience, "audience", nil, "Target audience(s) for the token (can be specified multiple times)")
	cmd.Flags().StringSliceVar(&scope, "scope", nil, "Requested scope(s) (can be specified multiple times)")
	cmd.Flags().StringSliceVar(&resource, "resource", nil, "Resource URI(s) (can be specified multiple times)")

	return cmd
}

// readToken reads a token from a file path or stdin (if path is "-")
func readToken(path string) (string, error) {
	var data []byte
	var err error

	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading from stdin: %w", err)
		}
	} else {
		data, err = os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("reading file %s: %w", path, err)
		}
	}

	// Clean up whitespace/newlines
	return strings.TrimSpace(string(data)), nil
}

func runExchange(cmd *cobra.Command, server, token string, audience, scope, resource []string) error {
	ctx := cmd.Context()

	// Clean up the token (remove whitespace/newlines that might have been introduced)
	token = strings.TrimSpace(token)

	// Validate inputs
	if token == "" {
		return fmt.Errorf("token is required")
	}

	// Basic JWT format validation
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts separated by '.', got %d parts (token length: %d chars)", len(parts), len(token))
	}

	if len(audience) == 0 {
		return fmt.Errorf("at least one --audience is required")
	}

	// Create exchange client
	client := exchange.NewClient(server)

	// Build request
	req := &exchange.ExchangeRequest{
		SubjectToken: token,
		Audience:     audience,
		Scope:        scope,
		Resource:     resource,
	}

	// Perform exchange
	fmt.Fprintf(os.Stderr, "Exchanging token with %s...\n", server)
	resp, err := client.ExchangeToken(ctx, req)
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
}
