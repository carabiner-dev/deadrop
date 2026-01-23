// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*TokenReadOptions)(nil)

var defaultTokenReadOptions = TokenReadOptions{}

// TokenOptions are the options to perform a token exchange
type TokenReadOptions struct {
	TokenPath string
}

func (to *TokenReadOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&to.TokenPath, "token", "", "Path to the token to exchange (or - for STDIN)")
}

func (to *TokenReadOptions) Validate() error {
	var errs = []error{}
	if to.TokenPath == "" {
		errs = append(errs, errors.New("path to token not specified"))
	}
	return errors.Join(errs...)
}

func (eo *TokenReadOptions) Config() *command.OptionsSetConfig {
	return nil
}

// readToken reads a token from a file path or stdin (if path is "-")
func (eo *TokenReadOptions) ReadToken() (string, error) {
	var data []byte
	var err error

	if eo.TokenPath == "-" {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading from stdin: %w", err)
		}
	} else {
		data, err = os.ReadFile(eo.TokenPath)
		if err != nil {
			return "", fmt.Errorf("reading file %s: %w", eo.TokenPath, err)
		}
	}

	// Clean up whitespace/newlines
	return strings.TrimSpace(string(data)), nil
}
