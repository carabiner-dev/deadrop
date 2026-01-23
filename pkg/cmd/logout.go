// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/deadrop/pkg/client/storage"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*LogoutOptions)(nil)

type LogoutOptions struct{}

var defaultLogoutOptions = LogoutOptions{}

func (lo *LogoutOptions) Validate() error {
	return nil
}

func (lo *LogoutOptions) AddFlags(cmd *cobra.Command) {
	// No flags for logout
}

func (lo *LogoutOptions) Config() *command.OptionsSetConfig {
	return nil
}

func AddLogout(parent *cobra.Command) {
	opts := defaultLogoutOptions

	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Clear cached token",
		Long:  `Remove the cached Carabiner token from disk.`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// Initialize token storage
			store, err := storage.NewTokenStorage()
			if err != nil {
				return fmt.Errorf("initializing token storage: %w", err)
			}

			// Delete token
			if err := store.DeleteToken(ctx); err != nil {
				return fmt.Errorf("deleting token: %w", err)
			}

			fmt.Println("✓ Token cleared successfully")
			return nil
		},
	}
	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}
