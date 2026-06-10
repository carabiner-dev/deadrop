// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
)

func TestNewServerOptions(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		opts := NewServerOptions()

		assert.Equal(t, DefaultServer, opts.Server)
		assert.Empty(t, opts.Prefix)
		assert.Empty(t, opts.Audience)
	})

	t.Run("with prefix", func(t *testing.T) {
		opts := NewServerOptions(WithPrefix("deadrop"))

		assert.Equal(t, DefaultServer, opts.Server)
		assert.Equal(t, "deadrop", opts.Prefix)
	})

	t.Run("with audience", func(t *testing.T) {
		opts := NewServerOptions(WithAudience(testAPIAudience))

		assert.Equal(t, DefaultServer, opts.Server)
		assert.Equal(t, []string{testAPIAudience}, opts.Audience)
	})

	t.Run("with multiple audiences", func(t *testing.T) {
		opts := NewServerOptions(WithAudience("https://api1.example.com", "https://api2.example.com"))

		assert.Equal(t, []string{"https://api1.example.com", "https://api2.example.com"}, opts.Audience)
	})

	t.Run("with prefix and audience", func(t *testing.T) {
		opts := NewServerOptions(
			WithPrefix("deadrop"),
			WithAudience(testAPIAudience),
		)

		assert.Equal(t, "deadrop", opts.Prefix)
		assert.Equal(t, []string{testAPIAudience}, opts.Audience)
	})

	t.Run("with disable persistence", func(t *testing.T) {
		opts := NewServerOptions(WithDisablePersistence())

		assert.True(t, opts.DisablePersistence)
	})
}

func TestServerOptions_Validate(t *testing.T) {
	tests := []struct {
		name    string
		opts    *ServerOptions
		wantErr bool
	}{
		{
			name:    "valid with defaults",
			opts:    NewServerOptions(),
			wantErr: false,
		},
		{
			name: "valid with custom server",
			opts: &ServerOptions{
				Server: "https://custom.example.com",
			},
			wantErr: false,
		},
		{
			name: "invalid empty server",
			opts: &ServerOptions{
				Server: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestServerOptions_Config(t *testing.T) {
	t.Run("without prefix", func(t *testing.T) {
		opts := NewServerOptions()
		cfg := opts.Config()

		require.NotNil(t, cfg)
		assert.Empty(t, cfg.FlagPrefix)
		assert.Contains(t, cfg.Flags, "server")
	})

	t.Run("with prefix", func(t *testing.T) {
		opts := NewServerOptions(WithPrefix("auth"))
		cfg := opts.Config()

		require.NotNil(t, cfg)
		assert.Equal(t, "auth", cfg.FlagPrefix)

		// LongFlag should return prefixed flag name
		assert.Equal(t, "auth-server", cfg.LongFlag("server"))
	})
}

func TestServerOptions_AddFlags(t *testing.T) {
	t.Run("without prefix", func(t *testing.T) {
		opts := NewServerOptions()
		cmd := &cobra.Command{}

		opts.AddFlags(cmd)

		serverFlag := cmd.PersistentFlags().Lookup("server")
		require.NotNil(t, serverFlag)
		assert.Equal(t, DefaultServer, serverFlag.DefValue)
	})

	t.Run("with prefix", func(t *testing.T) {
		opts := NewServerOptions(WithPrefix("auth"))
		cmd := &cobra.Command{}

		opts.AddFlags(cmd)

		// With prefix, flags should be prefixed
		serverFlag := cmd.PersistentFlags().Lookup("auth-server")
		require.NotNil(t, serverFlag)
		assert.Equal(t, DefaultServer, serverFlag.DefValue)
	})
}

func TestServerOptions_TokenSource(t *testing.T) {
	t.Run("requires audience", func(t *testing.T) {
		opts := NewServerOptions()
		_, err := opts.TokenSource(t.Context())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audience")
	})

	t.Run("uses preloaded audience", func(t *testing.T) {
		opts := NewServerOptions(WithAudience(testAPIAudience))
		// This should successfully create a TokenSource (audience is preloaded)
		source, err := opts.TokenSource(t.Context())
		require.NoError(t, err)
		assert.NotNil(t, source)
	})

	t.Run("override preloaded audience", func(t *testing.T) {
		opts := NewServerOptions(WithAudience("https://preloaded.example.com"))
		// Passing audience should override the preloaded one
		source, err := opts.TokenSource(t.Context(), "https://override.example.com")
		require.NoError(t, err)
		assert.NotNil(t, source)
	})

	t.Run("validates options", func(t *testing.T) {
		opts := &ServerOptions{Server: ""}
		_, err := opts.TokenSource(t.Context(), testAPIAudience)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid options")
	})
}

func TestServerOptions_TokenSourceWithRequest(t *testing.T) {
	t.Run("requires request", func(t *testing.T) {
		opts := NewServerOptions()
		_, err := opts.TokenSourceWithRequest(t.Context(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "request is required")
	})

	t.Run("validates options", func(t *testing.T) {
		opts := &ServerOptions{Server: ""}
		_, err := opts.TokenSourceWithRequest(t.Context(), &exchange.ExchangeRequest{
			Audience: []string{testAPIAudience},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid options")
	})
}
