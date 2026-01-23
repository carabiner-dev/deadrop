// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package oauth

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sync"
	"time"
)

// callbackResult holds the result from the OAuth callback
type callbackResult struct {
	Code  string
	State string
	Error string
}

// callbackServer manages the local HTTP server for OAuth callbacks
type callbackServer struct {
	server   *http.Server
	listener net.Listener
	result   chan callbackResult
	once     sync.Once
}

// newCallbackServer creates a new callback server on a random port
func newCallbackServer() (*callbackServer, error) {
	// Listen on localhost with random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("creating listener: %w", err)
	}

	cs := &callbackServer{
		listener: listener,
		result:   make(chan callbackResult, 1),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/callback", cs.handleCallback)

	cs.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return cs, nil
}

// start begins listening for callbacks
func (cs *callbackServer) start() {
	go cs.server.Serve(cs.listener) //nolint:errcheck
}

// getRedirectURL returns the callback URL for this server
func (cs *callbackServer) getRedirectURL() string {
	return fmt.Sprintf("http://%s/auth/callback", cs.listener.Addr().String())
}

// waitForCallback waits for the OAuth callback with timeout
func (cs *callbackServer) waitForCallback(ctx context.Context) (callbackResult, error) {
	select {
	case result := <-cs.result:
		return result, nil
	case <-ctx.Done():
		return callbackResult{}, ctx.Err()
	}
}

// shutdown gracefully shuts down the server
func (cs *callbackServer) shutdown(ctx context.Context) error {
	return cs.server.Shutdown(ctx)
}

// handleCallback processes the OAuth callback request
func (cs *callbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	// Send result to channel (only once)
	cs.once.Do(func() {
		cs.result <- callbackResult{
			Code:  code,
			State: state,
			Error: errorParam,
		}
	})

	// Render success or error page
	if errorParam != "" || code == "" {
		cs.renderErrorPage(w, errorParam, r.URL.Query().Get("error_description"))
	} else {
		cs.renderSuccessPage(w)
	}
}

// renderSuccessPage shows a success message to the user
func (cs *callbackServer) renderSuccessPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	tmpl := template.Must(template.New("success").Parse(successPageTemplate))
	tmpl.Execute(w, nil) //nolint:errcheck
}

// renderErrorPage shows an error message to the user
func (cs *callbackServer) renderErrorPage(w http.ResponseWriter, error, description string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)

	data := struct {
		Error       string
		Description string
	}{
		Error:       error,
		Description: description,
	}

	tmpl := template.Must(template.New("error").Parse(errorPageTemplate))
	tmpl.Execute(w, data) //nolint:errcheck
}

// HTML templates for callback pages
const successPageTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful</title>
    <style>
        body {
            font-family: "Ubuntu", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #b24202 0%, #e5790d 100%);
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
            text-align: center;
            max-width: 400px;
        }
        h1 { color: #333; margin: 0 0 1rem 0; }
        .checkmark {
            font-size: 64px;
            color: #4CAF50;
            margin-bottom: 1rem;
        }
        p { color: #666; margin: 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark">✓</div>
        <h1>Authentication Successful!</h1>
        <p>You can close this window and return to the terminal.</p>
    </div>
</body>
</html>`

const errorPageTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Authentication Failed</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 400px;
        }
        h1 { color: #333; margin: 0 0 1rem 0; }
        .error-icon {
            font-size: 64px;
            color: #f44336;
            margin-bottom: 1rem;
        }
        p { color: #666; margin: 0; }
        .error-details {
            background: #f5f5f5;
            padding: 1rem;
            border-radius: 5px;
            margin-top: 1rem;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">✗</div>
        <h1>Authentication Failed</h1>
        <p>An error occurred during authentication.</p>
        {{if .Error}}
        <div class="error-details">
            <strong>Error:</strong> {{.Error}}<br>
            {{if .Description}}<strong>Details:</strong> {{.Description}}{{end}}
        </div>
        {{end}}
        <p style="margin-top: 1rem;">Please close this window and try again.</p>
    </div>
</body>
</html>`
