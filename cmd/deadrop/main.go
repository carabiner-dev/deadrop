// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package main

import (
	"fmt"
	"os"

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
	rootCmd.AddCommand(newLoginCmd())
	rootCmd.AddCommand(newTokenCmd())
	rootCmd.AddCommand(newLogoutCmd())
	rootCmd.AddCommand(newVerifyCmd())
	rootCmd.AddCommand(newExchangeCmd())
	rootCmd.AddCommand(newVersionCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("deadrop version %s\n", version)
		},
	}
}
