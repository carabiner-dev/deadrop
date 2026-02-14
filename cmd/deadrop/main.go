// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/carabiner-dev/deadrop/pkg/cmd"
	"github.com/spf13/cobra"
)

var version = "dev" // Set via ldflags during build

func main() {
	rootCmd := &cobra.Command{
		Use:   "deadrop",
		Short: "Deadrop OAuth client for token exchange",
		Long: `Deadrop is a CLI client for performing OAuth login and exchanging
tokens with the Carabiner deadrop server.

It supports browser-based OAuth flows (similar to sigstore/cosign) and
automatically manages token caching using the XDG Base Directory specification.`,
	}

	// Add commands
	cmd.AddLogin(rootCmd)
	cmd.AddToken(rootCmd)
	cmd.AddLogout(rootCmd)
	cmd.AddVerify(rootCmd)
	cmd.AddExchange(rootCmd)
	cmd.AddWhoami(rootCmd)
	addVersion(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func addVersion(parent *cobra.Command) {
	parent.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("deadrop version %s\n", version)
		},
	})
}
