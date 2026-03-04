// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"testing"

	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOptions(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		opts := NewOptions()

		assert.Equal(t, DefaultServer, opts.Server)
		assert.Equal(t, DefaultLoginURL, opts.LoginURL)
		assert.Empty(t, opts.Prefix)
		assert.Empty(t, opts.Audience)
	})

	t.Run("with prefix", func(t *testing.T) {
		opts := NewOptions(WithPrefix("deadrop"))

		assert.Equal(t, DefaultServer, opts.Server)
		assert.Equal(t, DefaultLoginURL, opts.LoginURL)
		assert.Equal(t, "deadrop", opts.Prefix)
	})

	t.Run("with audience", func(t *testing.T) {
		opts := NewOptions(WithAudience("https://api.example.com"))

		assert.Equal(t, DefaultServer, opts.Server)
		assert.Equal(t, []string{"https://api.example.com"}, opts.Audience)
	})

	t.Run("with multiple audiences", func(t *testing.T) {
		opts := NewOptions(WithAudience("https://api1.example.com", "https://api2.example.com"))

		assert.Equal(t, []string{"https://api1.example.com", "https://api2.example.com"}, opts.Audience)
	})

	t.Run("with prefix and audience", func(t *testing.T) {
		opts := NewOptions(
			WithPrefix("deadrop"),
			WithAudience("https://api.example.com"),
		)

		assert.Equal(t, "deadrop", opts.Prefix)
		assert.Equal(t, []string{"https://api.example.com"}, opts.Audience)
	})

	t.Run("with disable persistence", func(t *testing.T) {
		opts := NewOptions(WithDisablePersistence())

		assert.True(t, opts.DisablePersistence)
	})
}

func TestOptions_Validate(t *testing.T) {
	tests := []struct {
		name    string
		opts    *Options
		wantErr bool
	}{
		{
			name:    "valid with defaults",
			opts:    NewOptions(),
			wantErr: false,
		},
		{
			name: "valid with custom server",
			opts: &Options{
				Server: "https://custom.example.com",
			},
			wantErr: false,
		},
		{
			name: "invalid empty server",
			opts: &Options{
				Server: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOptions_Config(t *testing.T) {
	t.Run("without prefix", func(t *testing.T) {
		opts := NewOptions()
		cfg := opts.Config()

		require.NotNil(t, cfg)
		assert.Empty(t, cfg.FlagPrefix)
		assert.Contains(t, cfg.Flags, "server")
		assert.Contains(t, cfg.Flags, "login-url")
	})

	t.Run("with prefix", func(t *testing.T) {
		opts := NewOptions(WithPrefix("auth"))
		cfg := opts.Config()

		require.NotNil(t, cfg)
		assert.Equal(t, "auth", cfg.FlagPrefix)

		// LongFlag should return prefixed flag name
		assert.Equal(t, "auth-server", cfg.LongFlag("server"))
		assert.Equal(t, "auth-login-url", cfg.LongFlag("login-url"))
	})
}

func TestOptions_AddFlags(t *testing.T) {
	t.Run("without prefix", func(t *testing.T) {
		opts := NewOptions()
		cmd := &cobra.Command{}

		opts.AddFlags(cmd)

		serverFlag := cmd.PersistentFlags().Lookup("server")
		require.NotNil(t, serverFlag)
		assert.Equal(t, DefaultServer, serverFlag.DefValue)

		loginURLFlag := cmd.PersistentFlags().Lookup("login-url")
		require.NotNil(t, loginURLFlag)
		assert.Equal(t, DefaultLoginURL, loginURLFlag.DefValue)
	})

	t.Run("with prefix", func(t *testing.T) {
		opts := NewOptions(WithPrefix("auth"))
		cmd := &cobra.Command{}

		opts.AddFlags(cmd)

		// With prefix, flags should be prefixed
		serverFlag := cmd.PersistentFlags().Lookup("auth-server")
		require.NotNil(t, serverFlag)
		assert.Equal(t, DefaultServer, serverFlag.DefValue)

		loginURLFlag := cmd.PersistentFlags().Lookup("auth-login-url")
		require.NotNil(t, loginURLFlag)
		assert.Equal(t, DefaultLoginURL, loginURLFlag.DefValue)
	})
}

func TestOptions_TokenSource(t *testing.T) {
	t.Run("requires audience", func(t *testing.T) {
		opts := NewOptions()
		_, err := opts.TokenSource(t.Context())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audience")
	})

	t.Run("uses preloaded audience", func(t *testing.T) {
		opts := NewOptions(WithAudience("https://api.example.com"))
		// This should successfully create a TokenSource (audience is preloaded)
		source, err := opts.TokenSource(t.Context())
		assert.NoError(t, err)
		assert.NotNil(t, source)
	})

	t.Run("override preloaded audience", func(t *testing.T) {
		opts := NewOptions(WithAudience("https://preloaded.example.com"))
		// Passing audience should override the preloaded one
		source, err := opts.TokenSource(t.Context(), "https://override.example.com")
		assert.NoError(t, err)
		assert.NotNil(t, source)
	})

	t.Run("validates options", func(t *testing.T) {
		opts := &Options{Server: ""}
		_, err := opts.TokenSource(t.Context(), "https://api.example.com")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid options")
	})
}

func TestOptions_TokenSourceWithRequest(t *testing.T) {
	t.Run("requires request", func(t *testing.T) {
		opts := NewOptions()
		_, err := opts.TokenSourceWithRequest(t.Context(), nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "request is required")
	})

	t.Run("validates options", func(t *testing.T) {
		opts := &Options{Server: ""}
		_, err := opts.TokenSourceWithRequest(t.Context(), &exchange.ExchangeRequest{
			Audience: []string{"https://api.example.com"},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid options")
	})
}
