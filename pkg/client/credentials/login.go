// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"time"

	"github.com/carabiner-dev/signer/sts"
	"github.com/chainguard-dev/clog"
	"golang.org/x/term"

	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
)

// BrowserLoginTimeout is the maximum time BrowserLogin waits for the user
// to complete the authentication flow in the browser.
const BrowserLoginTimeout = 5 * time.Minute

// Login obtains a Carabiner identity token from the deadrop server at
// serverURL.
//
// It first probes the registered STS providers (sts.DefaultProviders from
// carabiner-dev/signer) for ambient identity provider credentials, such as
// the GitHub Actions or GitLab CI OIDC tokens. The first available IdP token
// is exchanged at the deadrop server for a Carabiner identity (headless
// login).
//
// If no ambient credentials are found and the process is attached to a
// terminal, Login falls back to the interactive browser flow against the
// login service at loginURL. In non-interactive environments without
// ambient credentials, Login fails fast instead of waiting for a browser
// that will never open.
//
// Login returns the Carabiner identity token. It does not persist it; use
// SaveIdentity to store it in the server's session.
func Login(ctx context.Context, serverURL, loginURL string) (string, error) {
	if serverURL == "" {
		return "", errors.New("server URL is required")
	}

	// Probe the ambient STS providers in deterministic order. A provider
	// returning a nil token means its environment was not detected.
	names := make([]string, 0, len(sts.DefaultProviders))
	for name := range sts.DefaultProviders {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		idpToken, err := sts.DefaultProviders[name].Provide(ctx, serverURL)
		if err != nil {
			return "", fmt.Errorf("reading ambient credentials from %s: %w", name, err)
		}
		if idpToken == nil || idpToken.RawString == "" {
			continue
		}

		clog.FromContext(ctx).Debug("Found ambient credentials, performing headless login", "provider", name)
		token, err := HeadlessLogin(ctx, serverURL, idpToken.RawString)
		if err != nil {
			return "", fmt.Errorf("logging in with %s credentials: %w", name, err)
		}
		return token, nil
	}

	// No ambient credentials. Only fall back to the browser flow when a
	// human can actually complete it.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New(
			"no ambient credentials found and not running in a terminal " +
				"(in CI, ensure the workload has permission to mint OIDC tokens)",
		)
	}

	return BrowserLogin(ctx, loginURL)
}

// HeadlessLogin exchanges an identity provider token (for example a GitHub
// Actions OIDC token) for a Carabiner identity token at the deadrop server.
// The IdP token must have been minted with the deadrop server as audience.
func HeadlessLogin(ctx context.Context, serverURL, idpToken string) (string, error) {
	if serverURL == "" {
		return "", errors.New("server URL is required")
	}
	if idpToken == "" {
		return "", errors.New("identity provider token is required")
	}

	resp, err := exchange.NewClient(serverURL).ExchangeToken(ctx, &exchange.ExchangeRequest{
		SubjectToken: idpToken,
		Audience:     []string{serverURL},
	})
	if err != nil {
		return "", fmt.Errorf("exchanging identity provider token: %w", err)
	}

	return resp.AccessToken, nil
}

// BrowserLogin runs the interactive browser flow against the Carabiner login
// service at loginURL. It starts a callback server on a random loopback port,
// sends the user's browser to the login service and waits up to
// BrowserLoginTimeout for the service to redirect back with the Carabiner
// identity token.
//
// Progress messages are written to stderr; the token is returned, not
// persisted.
func BrowserLogin(ctx context.Context, loginURL string) (string, error) {
	if loginURL == "" {
		loginURL = DefaultLoginURL
	}

	// Start local callback server
	listenConfig := net.ListenConfig{}
	listener, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("starting callback server: %w", err)
	}
	defer listener.Close() //nolint:errcheck

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("unexpected listener address type %T", listener.Addr())
	}
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback", tcpAddr.Port)

	// Channels to receive the token or an error from the callback handler
	tokenCh := make(chan string, 1)
	errCh := make(chan error, 1)

	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}

			// Accept GET with token in query params (browser redirect from login service)
			token := r.URL.Query().Get("token")
			if token == "" {
				http.Error(w, "No token in request", http.StatusBadRequest)
				errCh <- errors.New("no token in callback")
				return
			}

			// Show success page to the user
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, loginSuccessPage) //nolint:errcheck // best-effort response to the browser

			tokenCh <- token
		}),
	}

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// Build login URL with our callback address
	browserURL, err := buildLoginURL(loginURL, callbackURL)
	if err != nil {
		return "", fmt.Errorf("building login URL: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Opening browser for authentication...\n")
	fmt.Fprintf(os.Stderr, "If the browser doesn't open, visit: %s\n", browserURL)

	if err := openBrowser(ctx, browserURL); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not open browser: %v\n", err)
	}

	fmt.Fprintf(os.Stderr, "Waiting for authentication...\n")

	select {
	case token := <-tokenCh:
		// Shutdown the server
		shutdownCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx) //nolint:errcheck,gosec

		return token, nil

	case err := <-errCh:
		return "", fmt.Errorf("authentication failed: %w", err)

	case <-ctx.Done():
		return "", ctx.Err()

	case <-time.After(BrowserLoginTimeout):
		return "", fmt.Errorf("authentication timed out after %v", BrowserLoginTimeout)
	}
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
func openBrowser(ctx context.Context, targetURL string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", targetURL) //nolint:gosec // URL comes from the configured login service
	case "linux":
		cmd = exec.CommandContext(ctx, "xdg-open", targetURL) //nolint:gosec // URL comes from the configured login service
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", targetURL) //nolint:gosec // URL comes from the configured login service
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	return cmd.Start()
}

// loginSuccessPage is shown in the browser after a successful login.
const loginSuccessPage = `<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful</title>
    <style>
        body { font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: linear-gradient(135deg, #b24202 0%, #e5790d 100%); }
        .card { background: white; padding: 2rem 3rem; border-radius: 10px; text-align: center; box-shadow: 0 10px 40px rgba(0,0,0,0.2); }
        .checkmark { width: 60px; height: 60px; border-radius: 50%; background: #34A853; color: white; font-size: 2rem; line-height: 60px; margin: 0 auto 1rem; }
        h1 { color: #333; margin-bottom: 0.5rem; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="card">
        <div class="checkmark">&#10003;</div>
        <h1>Authentication Successful!</h1>
        <p>You can close this tab and return to your terminal.</p>
    </div>
</body>
</html>`
