// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/deadrop/pkg/client/config"
	"github.com/carabiner-dev/deadrop/pkg/client/credentials"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = (*LoginOptions)(nil)

type LoginOptions struct {
	ServerOptions
	LoginURL   string
	PrintToken bool
	Force      bool
}

var defaultLoginOptions = LoginOptions{
	PrintToken: false,
}

// Validate the options set
func (lo *LoginOptions) Validate() error {
	var errs = []error{
		lo.ServerOptions.Validate(),
	}
	return errors.Join(errs...)
}

func (lo *LoginOptions) AddFlags(cmd *cobra.Command) {
	lo.ServerOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(&lo.LoginURL, "login-url", "", "Login service URL (default: https://login.carabiner.dev)")
	cmd.PersistentFlags().BoolVar(&lo.PrintToken, "print", defaultLoginOptions.PrintToken, "Print the token to stdout")
	cmd.PersistentFlags().BoolVar(&lo.Force, "force", false, "Force new login (ignore cached token)")
}

func (lo *LoginOptions) Config() *command.OptionsSetConfig {
	return nil
}

func AddLogin(parent *cobra.Command) {
	opts := defaultLoginOptions

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to obtain a Carabiner identity token",
		Long: `Authenticates with an identity provider via the Carabiner login service.

This command will:
1. Check for a cached valid identity token for the server (unless --force is used)
2. If no valid token exists, open a browser for authentication
3. Receive the Carabiner identity token from the login service
4. Save the identity token to a server-specific session directory

Sessions are stored in ~/.config/carabiner/<session-id>/identity.json with a
sessions.json file tracking which session belongs to which server.

Examples:
  # Login with Google (default)
  carabiner login

  # Login to a specific server
  carabiner login --server https://auth.carabiner.dev

  # Force new login (ignore cached token)
  carabiner login --force

  # Print token to stdout
  carabiner login --print`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// Load configuration
			cfg, err := config.LoadWithDefaults()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// Apply flag overrides
			if opts.Server != "" {
				cfg.ServerURL = opts.Server
			}
			if opts.LoginURL != "" {
				cfg.LoginURL = opts.LoginURL
			}

			// For login, we need the server URL to be set
			if cfg.ServerURL == "" {
				return fmt.Errorf("server URL is required (set via --server flag or DEADROP_SERVER env var)")
			}

			// Check for cached identity token for this server (unless --force)
			if !opts.Force {
				if token, exp, err := credentials.LoadIdentity(cfg.ServerURL); err == nil {
					timeUntil := time.Until(exp)
					fmt.Fprintf(os.Stderr, "Using cached identity for %s (expires in %v)\n", cfg.ServerURL, timeUntil.Round(time.Second))
					if opts.PrintToken {
						fmt.Println(token)
					}
					return nil
				}
			}

			// Start local callback server
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return fmt.Errorf("starting callback server: %w", err)
			}
			defer listener.Close()

			port := listener.Addr().(*net.TCPAddr).Port
			callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

			// Channel to receive the token
			tokenCh := make(chan string, 1)
			errCh := make(chan error, 1)

			// Start HTTP server to receive the token
			server := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/callback" {
						http.NotFound(w, r)
						return
					}

					if r.Method != http.MethodPost {
						http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
						return
					}

					var payload struct {
						Token string `json:"token"`
					}
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						http.Error(w, "Invalid request body", http.StatusBadRequest)
						errCh <- fmt.Errorf("invalid callback payload: %w", err)
						return
					}

					if payload.Token == "" {
						http.Error(w, "No token in request", http.StatusBadRequest)
						errCh <- errors.New("no token in callback")
						return
					}

					// Success - respond to the login service
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck

					tokenCh <- payload.Token
				}),
			}

			go func() {
				if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
					errCh <- err
				}
			}()

			// Build login URL
			loginURL, err := buildLoginURL(cfg.LoginURL, callbackURL)
			if err != nil {
				return fmt.Errorf("building login URL: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Opening browser for authentication...\n")
			fmt.Fprintf(os.Stderr, "If the browser doesn't open, visit: %s\n", loginURL)

			// Open browser
			if err := openBrowser(loginURL); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not open browser: %v\n", err)
			}

			// Wait for token or timeout
			fmt.Fprintf(os.Stderr, "Waiting for authentication...\n")

			select {
			case token := <-tokenCh:
				// Shutdown the server
				shutdownCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				server.Shutdown(shutdownCtx) //nolint:errcheck

				// Save the token
				if err := credentials.SaveIdentity(cfg.ServerURL, token); err != nil {
					return fmt.Errorf("saving identity: %w", err)
				}

				identityPath, _ := credentials.GetSessionIdentityPath(cfg.ServerURL)
				fmt.Fprintf(os.Stderr, "Authentication successful!\n")
				fmt.Fprintf(os.Stderr, "Identity saved to %s\n", identityPath)

				if opts.PrintToken {
					fmt.Println(token)
				}

				return nil

			case err := <-errCh:
				return fmt.Errorf("authentication failed: %w", err)

			case <-ctx.Done():
				return ctx.Err()

			case <-time.After(5 * time.Minute):
				return errors.New("authentication timed out after 5 minutes")
			}
		},
	}
	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}

// buildLoginURL constructs the login service URL with callback parameter.
// This sends the user to the provider selection page where they can choose
// their preferred authentication method.
func buildLoginURL(baseURL, callbackURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add callback_url parameter - user will select provider on the login page
	q := u.Query()
	q.Set("callback_url", callbackURL)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// openBrowser opens the default browser to the specified URL.
func openBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	return cmd.Start()
}
