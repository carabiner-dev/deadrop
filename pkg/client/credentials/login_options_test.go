// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLoginOptions(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		opts := NewLoginOptions()

		assert.Equal(t, DefaultLoginURL, opts.LoginURL)
		assert.False(t, opts.PrintToken)
		assert.False(t, opts.Force)
		assert.Empty(t, opts.Prefix)
	})

	t.Run("with prefix", func(t *testing.T) {
		opts := NewLoginOptions(WithLoginPrefix("auth"))

		assert.Equal(t, DefaultLoginURL, opts.LoginURL)
		assert.Equal(t, "auth", opts.Prefix)
	})
}

func TestLoginOptions_Validate(t *testing.T) {
	opts := NewLoginOptions()
	err := opts.Validate()
	assert.NoError(t, err)
}

func TestLoginOptions_Config(t *testing.T) {
	t.Run("without prefix", func(t *testing.T) {
		opts := NewLoginOptions()
		cfg := opts.Config()

		require.NotNil(t, cfg)
		assert.Empty(t, cfg.FlagPrefix)
		assert.Contains(t, cfg.Flags, "login-url")
		assert.Contains(t, cfg.Flags, "print")
		assert.Contains(t, cfg.Flags, "force")
	})

	t.Run("with prefix", func(t *testing.T) {
		opts := NewLoginOptions(WithLoginPrefix("auth"))
		cfg := opts.Config()

		require.NotNil(t, cfg)
		assert.Equal(t, "auth", cfg.FlagPrefix)

		// LongFlag should return prefixed flag name
		assert.Equal(t, "auth-login-url", cfg.LongFlag("login-url"))
		assert.Equal(t, "auth-print", cfg.LongFlag("print"))
		assert.Equal(t, "auth-force", cfg.LongFlag("force"))
	})
}

func TestLoginOptions_AddFlags(t *testing.T) {
	t.Run("without prefix", func(t *testing.T) {
		opts := NewLoginOptions()
		cmd := &cobra.Command{}

		opts.AddFlags(cmd)

		loginURLFlag := cmd.PersistentFlags().Lookup("login-url")
		require.NotNil(t, loginURLFlag)
		assert.Equal(t, DefaultLoginURL, loginURLFlag.DefValue)

		printFlag := cmd.PersistentFlags().Lookup("print")
		require.NotNil(t, printFlag)
		assert.Equal(t, "false", printFlag.DefValue)

		forceFlag := cmd.PersistentFlags().Lookup("force")
		require.NotNil(t, forceFlag)
		assert.Equal(t, "false", forceFlag.DefValue)
	})

	t.Run("with prefix", func(t *testing.T) {
		opts := NewLoginOptions(WithLoginPrefix("auth"))
		cmd := &cobra.Command{}

		opts.AddFlags(cmd)

		// With prefix, flags should be prefixed
		loginURLFlag := cmd.PersistentFlags().Lookup("auth-login-url")
		require.NotNil(t, loginURLFlag)
		assert.Equal(t, DefaultLoginURL, loginURLFlag.DefValue)

		printFlag := cmd.PersistentFlags().Lookup("auth-print")
		require.NotNil(t, printFlag)

		forceFlag := cmd.PersistentFlags().Lookup("auth-force")
		require.NotNil(t, forceFlag)
	})
}
