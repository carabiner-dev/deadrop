// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/carabiner-dev/command"
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
func (to *TokenReadOptions) ReadToken() (string, error) {
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

	// Default: read from carabiner identity file
	return readFromCarabinerIdentity()
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
func readFromCarabinerIdentity() (string, error) {
	identityPath, err := getCarabinerIdentityPath()
	if err != nil {
		return "", fmt.Errorf("getting identity path: %w", err)
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
