// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"net/http"
	"time"

	"github.com/carabiner-dev/deadrop/pkg/client/exchange"
)

// Option is a functional option for configuring the Manager.
type Option func(*Manager)

// WithServer sets the deadrop exchange server URL.
func WithServer(server string) Option {
	return func(m *Manager) {
		m.server = server
	}
}

// WithRefreshBuffer sets the refresh buffer as a fraction of token lifetime.
// For example, 0.2 means refresh when 20% of the token lifetime remains
// (i.e., at 80% of the way through the token's validity period).
// Default is 0.2.
func WithRefreshBuffer(buffer float64) Option {
	return func(m *Manager) {
		if buffer > 0 && buffer < 1 {
			m.refreshBuffer = buffer
		}
	}
}

// WithMaxRetries sets the maximum number of retry attempts for token exchange.
// Default is 5.
func WithMaxRetries(retries int) Option {
	return func(m *Manager) {
		if retries >= 0 {
			m.maxRetries = retries
		}
	}
}

// WithRetryInterval sets the initial retry interval for exponential backoff.
// Default is 1 second.
func WithRetryInterval(interval time.Duration) Option {
	return func(m *Manager) {
		if interval > 0 {
			m.retryInterval = interval
		}
	}
}

// WithHTTPClient sets a custom HTTP client for the exchange client.
func WithHTTPClient(client *http.Client) Option {
	return func(m *Manager) {
		if client != nil {
			m.client = &exchange.Client{
				ServerURL:  m.server,
				HTTPClient: client,
			}
		}
	}
}

// WithTokenSource adds one or more TokenSources for the central identity token.
// Multiple sources are tried in order until one succeeds.
// If no sources are provided via this option, the Manager uses the default sources:
// 1. CARABINER_CREDENTIALS environment variable
// 2. os.UserConfigDir()/carabiner/identity.json
func WithTokenSource(sources ...TokenSource) Option {
	return func(m *Manager) {
		m.centralSources = append(m.centralSources, sources...)
	}
}
