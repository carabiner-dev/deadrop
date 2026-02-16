// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/deadrop/pkg/client/credentials"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*TokenReadOptions)(nil)

var defaultTokenReadOptions = TokenReadOptions{}

// TokenReadOptions are the options to read a token from various sources
type TokenReadOptions struct {
	TokenPath string
}

func (to *TokenReadOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&to.TokenPath, "token", "", "Path to the token file (defaults to carabiner identity)")
}

func (to *TokenReadOptions) Validate() error {
	// No validation needed - we have a default fallback
	return nil
}

func (to *TokenReadOptions) Config() *command.OptionsSetConfig {
	return nil
}

// ReadToken reads a token with the following precedence:
// 1. stdin (if "-" is specified or data is piped)
// 2. --token flag (explicit file path)
// 3. carabiner identity file (~/.config/carabiner/identity.json)
//
// Note: This uses context.Background() for auto-renewal. Use ReadTokenWithContext
// for better context control.
func (to *TokenReadOptions) ReadToken() (string, error) {
	return to.ReadTokenWithContext(context.Background())
}

// ReadTokenWithContext reads a token with the following precedence:
// 1. stdin (if "-" is specified or data is piped)
// 2. --token flag (explicit file path)
// 3. carabiner identity file (with auto-renewal if about to expire)
func (to *TokenReadOptions) ReadTokenWithContext(ctx context.Context) (string, error) {
	// Check if reading from stdin
	if to.TokenPath == "-" {
		return readFromStdin()
	}

	// Check if --token was explicitly provided
	if to.TokenPath != "" {
		return readFromFile(to.TokenPath)
	}

	// Check if stdin has data (piped input without explicit "-")
	if hasStdinData() {
		return readFromStdin()
	}

	// Default: read from carabiner identity file with auto-renewal
	return readFromCarabinerIdentity(ctx)
}

// hasStdinData checks if there's data available on stdin (piped input)
func hasStdinData() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	// Check if stdin is a pipe or has data
	return (stat.Mode() & os.ModeCharDevice) == 0
}

// readFromStdin reads token data from stdin
func readFromStdin() (string, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading from stdin: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("no token data received from stdin")
	}
	return token, nil
}

// readFromFile reads token data from a file
func readFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading file %s: %w", path, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	return token, nil
}

// readFromCarabinerIdentity reads the token from the default carabiner identity file
// with auto-renewal if the token is about to expire.
func readFromCarabinerIdentity(ctx context.Context) (string, error) {
	// Get the default session to find the server URL
	_, serverURL, err := credentials.GetDefaultSession()
	if err != nil {
		// No session exists, try the legacy path for backwards compatibility
		return readFromCarabinerIdentityLegacy()
	}

	// Load with auto-renewal
	token, _, renewed, err := credentials.LoadIdentityWithRenewal(ctx, serverURL)
	if err != nil {
		if err == credentials.ErrTokenExpired {
			return "", fmt.Errorf("identity token has expired, please run 'carabiner login' to authenticate again")
		}
		return "", fmt.Errorf("loading carabiner identity: %w", err)
	}

	if renewed {
		fmt.Fprintf(os.Stderr, "Token was automatically renewed\n")
	}

	return token, nil
}

// readFromCarabinerIdentityLegacy reads from the legacy identity file path for backwards compatibility.
func readFromCarabinerIdentityLegacy() (string, error) {
	identityPath, pathErr := credentials.GetDefaultIdentityPath()
	if pathErr != nil {
		return "", fmt.Errorf("no carabiner identity found (run 'deadrop login' first)")
	}

	data, err := os.ReadFile(identityPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no carabiner identity found at %s (run 'deadrop login' first)", identityPath)
		}
		return "", fmt.Errorf("reading identity file: %w", err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("carabiner identity file is empty")
	}

	return token, nil
}
