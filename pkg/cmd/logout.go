// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/deadrop/pkg/client/config"
	"github.com/carabiner-dev/deadrop/pkg/client/credentials"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*LogoutOptions)(nil)

type LogoutOptions struct {
	ServerOptions
	All bool
}

var defaultLogoutOptions = LogoutOptions{}

func (lo *LogoutOptions) Validate() error {
	return lo.ServerOptions.Validate()
}

func (lo *LogoutOptions) AddFlags(cmd *cobra.Command) {
	lo.ServerOptions.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(&lo.All, "all", false, "Clear all cached identities")
}

func (lo *LogoutOptions) Config() *command.OptionsSetConfig {
	return nil
}

func AddLogout(parent *cobra.Command) {
	opts := defaultLogoutOptions

	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Clear cached identity",
		Long: `Remove the cached Carabiner identity from disk.

By default, clears the identity for the configured server or default session.
Use --all to clear all cached identities.

Examples:
  # Logout from default server
  carabiner logout

  # Logout from a specific server
  carabiner logout --server https://auth.carabiner.dev

  # Clear all cached identities
  carabiner logout --all`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.All {
				// Clear all sessions
				sessions, _, err := credentials.ListSessions()
				if err != nil {
					return fmt.Errorf("listing sessions: %w", err)
				}

				if len(sessions) == 0 {
					fmt.Fprintln(os.Stderr, "No cached identities found")
					return nil
				}

				for serverURL := range sessions {
					if err := credentials.DeleteIdentity(serverURL); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to delete identity for %s: %v\n", serverURL, err)
					} else {
						fmt.Fprintf(os.Stderr, "Cleared identity for %s\n", serverURL)
					}
				}

				fmt.Fprintln(os.Stderr, "All identities cleared")
				return nil
			}

			// Load configuration
			cfg, err := config.LoadWithDefaults()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// Apply flag overrides
			if opts.Server != "" {
				cfg.ServerURL = opts.Server
			}

			// Determine which server to use
			serverURL := cfg.ServerURL
			if serverURL == "" {
				// Try to get the default session
				_, defaultServer, err := credentials.GetDefaultSession()
				if err != nil {
					fmt.Fprintln(os.Stderr, "No cached identities found")
					return nil
				}
				serverURL = defaultServer
			}

			// Delete the identity
			if err := credentials.DeleteIdentity(serverURL); err != nil {
				return fmt.Errorf("deleting identity for %s: %w", serverURL, err)
			}

			fmt.Fprintf(os.Stderr, "Identity cleared for %s\n", serverURL)
			return nil
		},
	}
	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
