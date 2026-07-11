// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCE holds a generated PKCE verifier and its S256 code challenge (RFC 7636).
type PKCE struct {
	// Verifier is the secret the app holds between starting the flow and
	// redeeming the code. It must never be sent to the browser.
	Verifier string
	// Challenge is the S256 code_challenge sent to the login service in the
	// authorization URL.
	Challenge string
}

// GeneratePKCE generates a random PKCE verifier and its S256 challenge.
func GeneratePKCE() (*PKCE, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generating PKCE verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	return &PKCE{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}
