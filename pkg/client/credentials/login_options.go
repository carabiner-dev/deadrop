// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

const (
	flagLoginURL   = "login-url"
	flagPrintToken = "print"
	flagForce      = "force"
)

var _ command.OptionsSet = (*LoginOptions)(nil)

// LoginOptionsOption is a functional option for configuring LoginOptions.
type LoginOptionsOption func(*LoginOptions)

// WithLoginPrefix sets the flag prefix for the login options.
func WithLoginPrefix(prefix string) LoginOptionsOption {
	return func(o *LoginOptions) {
		o.Prefix = prefix
	}
}

// LoginOptions is an OptionsSet for configuring login behavior in CLI tools.
// It provides flags for the login URL, print token, and force login.
//
// Example usage:
//
//	type MyOptions struct {
//	    credentials.Options
//	    credentials.LoginOptions
//	}
//
//	func (o *MyOptions) AddFlags(cmd *cobra.Command) {
//	    o.Options.AddFlags(cmd)
//	    o.LoginOptions.AddFlags(cmd)
//	}
type LoginOptions struct {
	// LoginURL is the login service URL for interactive authentication.
	LoginURL string

	// PrintToken prints the token to stdout after successful login.
	PrintToken bool

	// Force forces a new login even if a valid cached token exists.
	Force bool

	// Prefix is an optional prefix for flag names.
	Prefix string
}

// NewLoginOptions creates a new LoginOptions with default values.
func NewLoginOptions(opts ...LoginOptionsOption) *LoginOptions {
	o := &LoginOptions{
		LoginURL: DefaultLoginURL,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// Config returns the OptionsSetConfig for this options set.
func (o *LoginOptions) Config() *command.OptionsSetConfig {
	return &command.OptionsSetConfig{
		FlagPrefix: o.Prefix,
		Flags: map[string]command.FlagConfig{
			flagLoginURL: {
				Long: "login-url",
				Help: "Login service URL for interactive authentication",
			},
			flagPrintToken: {
				Long: "print",
				Help: "Print the token to stdout after login",
			},
			flagForce: {
				Long: "force",
				Help: "Force new login (ignore cached token)",
			},
		},
	}
}

// Validate validates the login options.
func (o *LoginOptions) Validate() error {
	return nil
}

// AddFlags adds the login flags to the command.
func (o *LoginOptions) AddFlags(cmd *cobra.Command) {
	cfg := o.Config()

	cmd.PersistentFlags().StringVar(
		&o.LoginURL,
		cfg.LongFlag(flagLoginURL),
		DefaultLoginURL,
		cfg.HelpText(flagLoginURL),
	)

	cmd.PersistentFlags().BoolVar(
		&o.PrintToken,
		cfg.LongFlag(flagPrintToken),
		false,
		cfg.HelpText(flagPrintToken),
	)

	cmd.PersistentFlags().BoolVar(
		&o.Force,
		cfg.LongFlag(flagForce),
		false,
		cfg.HelpText(flagForce),
	)
}
