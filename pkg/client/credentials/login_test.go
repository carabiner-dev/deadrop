// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/carabiner-dev/signer/sts"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

// fakeSTSProvider is a configurable sts.Provider for tests.
type fakeSTSProvider struct {
	token    string
	err      error
	audience string // records the audience it was called with
}

func (f *fakeSTSProvider) Provide(_ context.Context, audience string) (*oauthflow.OIDCIDToken, error) {
	f.audience = audience
	if f.err != nil {
		return nil, f.err
	}
	if f.token == "" {
		return nil, nil //nolint:nilnil // nil token means provider not available, per the sts contract
	}
	return &oauthflow.OIDCIDToken{RawString: f.token}, nil
}

// disableAmbientEnv clears the env vars the default STS providers probe so
// tests behave the same locally and in CI.
func disableAmbientEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("SIGSTORE_ID_TOKEN", "")
}

// newExchangeServerForLogin returns an httptest server implementing the
// /token endpoint, capturing the subject token and requested audiences it
// receives.
func newExchangeServerForLogin(t *testing.T, carabinerToken string, subjectToken *string, audience *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		*subjectToken = r.FormValue("subject_token")
		if audience != nil {
			*audience = r.Form["audience"]
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"access_token": "` + carabinerToken + `", "token_type": "Bearer", "expires_in": 3600}`)); err != nil {
			t.Errorf("writing response: %v", err)
		}
	}))
}

func TestHeadlessLogin(t *testing.T) {
	carabinerToken := createTestJWT(time.Now().Add(time.Hour))
	ctx := context.Background()

	t.Run("exchanges idp token", func(t *testing.T) {
		var (
			gotSubject  string
			gotAudience []string
		)
		server := newExchangeServerForLogin(t, carabinerToken, &gotSubject, &gotAudience)
		defer server.Close()

		token, err := HeadlessLogin(ctx, server.URL, "idp-token")
		if err != nil {
			t.Fatalf("HeadlessLogin() error: %v", err)
		}
		if token != carabinerToken {
			t.Errorf("HeadlessLogin() = %q, want %q", token, carabinerToken)
		}
		if gotSubject != "idp-token" {
			t.Errorf("subject_token = %q, want %q", gotSubject, "idp-token")
		}
		// The identity must be minted for the API audience (what the server's
		// identity exchangers accept), not for the exchange server itself.
		if len(gotAudience) != 1 || gotAudience[0] != DefaultIdentityAudience {
			t.Errorf("audience = %v, want [%s]", gotAudience, DefaultIdentityAudience)
		}
	})

	t.Run("requires server URL", func(t *testing.T) {
		if _, err := HeadlessLogin(ctx, "", "idp-token"); err == nil {
			t.Error("HeadlessLogin() expected error for empty server URL")
		}
	})

	t.Run("requires idp token", func(t *testing.T) {
		if _, err := HeadlessLogin(ctx, "https://auth.example.com", ""); err == nil {
			t.Error("HeadlessLogin() expected error for empty token")
		}
	})

	t.Run("propagates exchange errors", func(t *testing.T) {
		failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error": "invalid_grant", "error_description": "unknown issuer"}`, http.StatusBadRequest)
		}))
		defer failServer.Close()

		if _, err := HeadlessLogin(ctx, failServer.URL, "idp-token"); err == nil {
			t.Error("HeadlessLogin() expected error for failed exchange")
		}
	})
}

func TestLogin(t *testing.T) {
	carabinerToken := createTestJWT(time.Now().Add(time.Hour))
	ctx := context.Background()

	t.Run("requires server URL", func(t *testing.T) {
		if _, err := Login(ctx, "", ""); err == nil {
			t.Error("Login() expected error for empty server URL")
		}
	})

	t.Run("uses ambient provider when available", func(t *testing.T) {
		disableAmbientEnv(t)

		var gotSubject string
		server := newExchangeServerForLogin(t, carabinerToken, &gotSubject, nil)
		defer server.Close()

		provider := &fakeSTSProvider{token: "ambient-idp-token"} //nolint:gosec // test value, not a credential
		sts.RegisterProvider("test-fake", provider)
		defer sts.UnregisterProvider("test-fake", provider)

		token, err := Login(ctx, server.URL, "")
		if err != nil {
			t.Fatalf("Login() error: %v", err)
		}
		if token != carabinerToken {
			t.Errorf("Login() = %q, want %q", token, carabinerToken)
		}
		if gotSubject != "ambient-idp-token" {
			t.Errorf("subject_token = %q, want %q", gotSubject, "ambient-idp-token")
		}
		if provider.audience != server.URL {
			t.Errorf("provider audience = %q, want %q", provider.audience, server.URL)
		}
	})

	t.Run("fails on provider error", func(t *testing.T) {
		disableAmbientEnv(t)

		provider := &fakeSTSProvider{err: errors.New("provider exploded")}
		sts.RegisterProvider("test-fake", provider)
		defer sts.UnregisterProvider("test-fake", provider)

		if _, err := Login(ctx, "https://auth.example.com", ""); err == nil {
			t.Error("Login() expected error when provider fails")
		}
	})

	t.Run("fails fast without ambient credentials or terminal", func(t *testing.T) {
		disableAmbientEnv(t)

		// Tests never run attached to a TTY, so with no ambient
		// credentials Login must fail instead of starting the browser flow.
		_, err := Login(ctx, "https://auth.example.com", "")
		if err == nil {
			t.Fatal("Login() expected error in non-terminal environment")
		}
	})
}
