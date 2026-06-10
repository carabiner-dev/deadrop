// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"errors"
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
)

const (
	flagServer = "server"
)

var _ command.OptionsSet = (*ServerOptions)(nil)

// DefaultServer is the default deadrop exchange server URL.
const DefaultServer = "https://auth.carabiner.dev"

// DefaultLoginURL is the default login URL for the Carabiner login service.
const DefaultLoginURL = "https://login.carabiner.dev"

// ServerOptionsOption is a functional option for configuring ServerOptions.
type ServerOptionsOption func(*ServerOptions)

// WithPrefix sets the flag prefix for the options.
// For example, WithPrefix("deadrop") results in flags like --deadrop-server.
func WithPrefix(prefix string) ServerOptionsOption {
	return func(o *ServerOptions) {
		o.Prefix = prefix
	}
}

// WithAudience sets the default audience for token exchange.
// This can be overridden when calling TokenSource().
func WithAudience(audience ...string) ServerOptionsOption {
	return func(o *ServerOptions) {
		o.Audience = audience
	}
}

// WithDisablePersistence disables token caching to disk.
func WithDisablePersistence() ServerOptionsOption {
	return func(o *ServerOptions) {
		o.DisablePersistence = true
	}
}

// ServerOptions is an ServerOptionsSet for configuring deadrop credentials in CLI tools.
// It provides the --server flag and methods to obtain TokenSource instances
// for specific audiences.
//
// Example usage in a CLI tool:
//
//	type MyServerOptions struct {
//	    credentials.ServerOptions
//	    // other options...
//	}
//
//	func (o *MyServerOptions) AddFlags(cmd *cobra.Command) {
//	    o.ServerOptions.AddFlags(cmd)
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
//	opts := credentials.NewServerOptions(
//	    credentials.WithPrefix("deadrop"),
//	    credentials.WithAudience("https://api.example.com"),
//	)
type ServerOptions struct {
	// Server is the deadrop exchange server URL.
	Server string

	// Prefix is an optional prefix for flag names (e.g., "deadrop" -> "--deadrop-server").
	Prefix string

	// Audience is the default audience for token exchange.
	Audience []string

	// DisablePersistence disables token caching to disk.
	DisablePersistence bool
}

// NewServerOptions creates a new ServerOptions with default values.
// Use functional options to customize the configuration.
//
// Examples:
//
//	// Default options
//	opts := credentials.NewServerOptions()
//
//	// With prefix
//	opts := credentials.NewServerOptions(credentials.WithPrefix("deadrop"))
//
//	// With prefix and audience
//	opts := credentials.NewServerOptions(
//	    credentials.WithPrefix("deadrop"),
//	    credentials.WithAudience("https://api.example.com"),
//	)
func NewServerOptions(opts ...ServerOptionsOption) *ServerOptions {
	o := &ServerOptions{
		Server: DefaultServer,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// Config returns the OptionsSetConfig for this options set.
func (o *ServerOptions) Config() *command.OptionsSetConfig {
	return &command.OptionsSetConfig{
		FlagPrefix: o.Prefix,
		Flags: map[string]command.FlagConfig{
			flagServer: {
				Long: "server",
				Help: "Deadrop exchange server URL",
			},
		},
	}
}

// Validate validates the options.
func (o *ServerOptions) Validate() error {
	if o.Server == "" {
		return errors.New("deadrop server URL is required")
	}
	return nil
}

// AddFlags adds the deadrop credential flags to the command.
func (o *ServerOptions) AddFlags(cmd *cobra.Command) {
	cfg := o.Config()

	cmd.PersistentFlags().StringVar(
		&o.Server,
		cfg.LongFlag(flagServer),
		DefaultServer,
		cfg.HelpText(flagServer),
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
//	opts := credentials.NewServerOptions(credentials.WithAudience("https://api.example.com"))
//	source, err := opts.TokenSource(ctx)
func (o *ServerOptions) TokenSource(ctx context.Context, audience ...string) (TokenSource, error) {
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
func (o *ServerOptions) TokenSourceWithRequest(ctx context.Context, req *exchange.ExchangeRequest) (TokenSource, error) {
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
func (o *ServerOptions) Manager(ctx context.Context) (*Manager, error) {
	if err := o.Validate(); err != nil {
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	return NewManager(ctx, WithServer(o.Server))
}
