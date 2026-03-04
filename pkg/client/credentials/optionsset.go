// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"errors"
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
	"github.com/spf13/cobra"
)

const (
	flagServer   = "server"
	flagLoginURL = "login-url"
)

var _ command.OptionsSet = (*Options)(nil)

// DefaultServer is the default deadrop exchange server URL.
const DefaultServer = "https://auth.carabiner.dev"

// DefaultLoginURL is the default login URL for the Carabiner login service.
const DefaultLoginURL = "https://login.carabiner.dev"

// OptionsOption is a functional option for configuring Options.
type OptionsOption func(*Options)

// WithPrefix sets the flag prefix for the options.
// For example, WithPrefix("deadrop") results in flags like --deadrop-server.
func WithPrefix(prefix string) OptionsOption {
	return func(o *Options) {
		o.Prefix = prefix
	}
}

// WithAudience sets the default audience for token exchange.
// This can be overridden when calling TokenSource().
func WithAudience(audience ...string) OptionsOption {
	return func(o *Options) {
		o.Audience = audience
	}
}

// WithDisablePersistence disables token caching to disk.
func WithDisablePersistence() OptionsOption {
	return func(o *Options) {
		o.DisablePersistence = true
	}
}

// Options is an OptionsSet for configuring deadrop credentials in CLI tools.
// It provides flags for the exchange server and login URL, and methods
// to obtain TokenSource instances for specific audiences.
//
// Example usage in a CLI tool:
//
//	type MyOptions struct {
//	    credentials.Options
//	    // other options...
//	}
//
//	func (o *MyOptions) AddFlags(cmd *cobra.Command) {
//	    o.Options.AddFlags(cmd)
//	    // add other flags...
//	}
//
//	// In command handler:
//	source, err := opts.TokenSource(ctx)
//	if err != nil {
//	    return err
//	}
//	token, err := source.Token(ctx)
//
// Example with prefix and audience:
//
//	opts := credentials.NewOptions(
//	    credentials.WithPrefix("deadrop"),
//	    credentials.WithAudience("https://api.example.com"),
//	)
type Options struct {
	// Server is the deadrop exchange server URL.
	Server string

	// LoginURL is the login service URL for interactive authentication.
	LoginURL string

	// Prefix is an optional prefix for flag names (e.g., "deadrop" -> "--deadrop-server").
	Prefix string

	// Audience is the default audience for token exchange.
	Audience []string

	// DisablePersistence disables token caching to disk.
	DisablePersistence bool
}

// NewOptions creates a new Options with default values.
// Use functional options to customize the configuration.
//
// Examples:
//
//	// Default options
//	opts := credentials.NewOptions()
//
//	// With prefix
//	opts := credentials.NewOptions(credentials.WithPrefix("deadrop"))
//
//	// With prefix and audience
//	opts := credentials.NewOptions(
//	    credentials.WithPrefix("deadrop"),
//	    credentials.WithAudience("https://api.example.com"),
//	)
func NewOptions(opts ...OptionsOption) *Options {
	o := &Options{
		Server:   DefaultServer,
		LoginURL: DefaultLoginURL,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// Config returns the OptionsSetConfig for this options set.
func (o *Options) Config() *command.OptionsSetConfig {
	return &command.OptionsSetConfig{
		FlagPrefix: o.Prefix,
		Flags: map[string]command.FlagConfig{
			flagServer: {
				Long: "server",
				Help: "Deadrop exchange server URL",
			},
			flagLoginURL: {
				Long: "login-url",
				Help: "Login service URL for interactive authentication",
			},
		},
	}
}

// Validate validates the options.
func (o *Options) Validate() error {
	if o.Server == "" {
		return errors.New("deadrop server URL is required")
	}
	return nil
}

// AddFlags adds the deadrop credential flags to the command.
func (o *Options) AddFlags(cmd *cobra.Command) {
	cfg := o.Config()

	cmd.PersistentFlags().StringVar(
		&o.Server,
		cfg.LongFlag(flagServer),
		DefaultServer,
		cfg.HelpText(flagServer),
	)

	cmd.PersistentFlags().StringVar(
		&o.LoginURL,
		cfg.LongFlag(flagLoginURL),
		DefaultLoginURL,
		cfg.HelpText(flagLoginURL),
	)
}

// TokenSource returns a TokenSource for the given audience.
// If no audience is provided, uses the audience configured via WithAudience().
// The returned TokenSource handles token exchange and automatic renewal.
//
// Example:
//
//	// With audience specified at call time
//	source, err := opts.TokenSource(ctx, "https://api.example.com")
//
//	// Using preloaded audience from WithAudience()
//	opts := credentials.NewOptions(credentials.WithAudience("https://api.example.com"))
//	source, err := opts.TokenSource(ctx)
func (o *Options) TokenSource(ctx context.Context, audience ...string) (TokenSource, error) {
	// Use provided audience, or fall back to preloaded audience
	aud := audience
	if len(aud) == 0 {
		aud = o.Audience
	}

	if len(aud) == 0 {
		return nil, errors.New("at least one audience is required (use WithAudience() or pass audience to TokenSource())")
	}

	if err := o.Validate(); err != nil {
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	req := &exchange.ExchangeRequest{
		Audience: aud,
	}

	opts := []ServiceTokenSourceOption{}
	if !o.DisablePersistence {
		opts = append(opts, WithServicePersistence())
	}

	return NewServiceTokenSource(req, o.Server, opts...)
}

// TokenSourceWithRequest returns a TokenSource for the given exchange request.
// This allows specifying additional exchange parameters like scope and resource.
//
// Example:
//
//	source, err := opts.TokenSourceWithRequest(ctx, &exchange.ExchangeRequest{
//	    Audience: []string{"https://api.example.com"},
//	    Scope:    []string{"read", "write"},
//	})
func (o *Options) TokenSourceWithRequest(ctx context.Context, req *exchange.ExchangeRequest) (TokenSource, error) {
	if req == nil {
		return nil, errors.New("exchange request is required")
	}

	if err := o.Validate(); err != nil {
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	opts := []ServiceTokenSourceOption{}
	if !o.DisablePersistence {
		opts = append(opts, WithServicePersistence())
	}

	return NewServiceTokenSource(req, o.Server, opts...)
}

// Manager returns a new credentials Manager configured with these options.
// The Manager provides more control over token lifecycle than TokenSource.
//
// Example:
//
//	mgr, err := opts.Manager(ctx)
//	if err != nil {
//	    return err
//	}
//	defer mgr.Close()
//
//	err = mgr.Register(ctx, "api", &exchange.ExchangeRequest{
//	    Audience: []string{"https://api.example.com"},
//	})
//	token, err := mgr.Token(ctx, "api")
func (o *Options) Manager(ctx context.Context) (*Manager, error) {
	if err := o.Validate(); err != nil {
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	return NewManager(ctx, WithServer(o.Server))
}
