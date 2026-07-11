// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePKCE(t *testing.T) {
	p, err := GeneratePKCE()
	require.NoError(t, err)
	require.NotEmpty(t, p.Verifier)
	require.NotEmpty(t, p.Challenge)

	// Challenge must be the S256 of the verifier.
	sum := sha256.Sum256([]byte(p.Verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	assert.Equal(t, want, p.Challenge)

	// Two generations differ.
	p2, err := GeneratePKCE()
	require.NoError(t, err)
	assert.NotEqual(t, p.Verifier, p2.Verifier)
}

func TestAuthCodeURL(t *testing.T) {
	got, err := AuthCodeURL("https://login.carabiner.dev", AuthCodeParams{
		CallbackURL: "https://app.carabiner.dev/api/v1/auth/callback",
		Scopes:      []string{"identities", "email"},
		State:       "state-xyz",
		Challenge:   "the-challenge",
	})
	require.NoError(t, err)

	u, err := url.Parse(got)
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "https://app.carabiner.dev/api/v1/auth/callback", q.Get("callback_url"))
	assert.Equal(t, "identities email", q.Get("scope"))
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, "the-challenge", q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, "state-xyz", q.Get("state"))
}

func TestAuthCodeURLOmitsEmptyScopeAndState(t *testing.T) {
	got, err := AuthCodeURL("https://login.carabiner.dev", AuthCodeParams{
		CallbackURL: "https://app/cb",
		Challenge:   "c",
	})
	require.NoError(t, err)
	u, err := url.Parse(got)
	require.NoError(t, err)
	q := u.Query()
	assert.False(t, q.Has("scope"))
	assert.False(t, q.Has("state"))
}

func TestAuthCodeURLValidation(t *testing.T) {
	_, err := AuthCodeURL("https://login", AuthCodeParams{Challenge: "c"})
	require.Error(t, err, "missing callback should error")

	_, err = AuthCodeURL("https://login", AuthCodeParams{CallbackURL: "https://app/cb"})
	require.Error(t, err, "missing challenge should error")
}

func TestRedeemSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/auth/token", r.URL.Path)
		assert.Equal(t, "authorization_code", r.PostFormValue("grant_type"))
		assert.Equal(t, "CODE", r.PostFormValue("code"))
		assert.Equal(t, "VERIFIER", r.PostFormValue("code_verifier"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck,gosec // test handler
			"access_token": "the.jwt",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	tok, err := NewClient(srv.URL).Redeem(context.Background(), "CODE", "VERIFIER")
	require.NoError(t, err)
	assert.Equal(t, "the.jwt", tok.AccessToken)
	assert.Equal(t, "Bearer", tok.TokenType)
	assert.Equal(t, int64(3600), tok.ExpiresIn)
}

func TestRedeemError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck,gosec // test handler
			"error":             "invalid_grant",
			"error_description": "code is invalid or expired",
		})
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).Redeem(context.Background(), "CODE", "VERIFIER")
	require.Error(t, err)
	var le *Error
	require.ErrorAs(t, err, &le)
	assert.Equal(t, http.StatusBadRequest, le.StatusCode)
	assert.Equal(t, "invalid_grant", le.Code)
	assert.Equal(t, "code is invalid or expired", le.Description)
}

func TestRedeemValidation(t *testing.T) {
	c := NewClient("https://login.carabiner.dev")
	_, err := c.Redeem(context.Background(), "", "v")
	require.Error(t, err)
	_, err = c.Redeem(context.Background(), "c", "")
	require.Error(t, err)
}
