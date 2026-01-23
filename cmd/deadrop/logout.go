// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package main

import (
	"fmt"

	"github.com/carabiner-dev/deadrop/pkg/client/storage"
	"github.com/spf13/cobra"
)

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Clear cached token",
		Long:  `Remove the cached Carabiner token from disk.`,
		RunE:  runLogout,
	}
}

func runLogout(cmd *cobra.Command, args []string) error {
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
}
