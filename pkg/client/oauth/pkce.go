// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCEChallenge holds PKCE code verifier and challenge
type PKCEChallenge struct {
	Verifier  string
	Challenge string
	Method    string // Always "S256"
}

// GeneratePKCEChallenge generates a new PKCE code verifier and challenge
// Following RFC 7636 specifications
func GeneratePKCEChallenge() (*PKCEChallenge, error) {
	// Generate code verifier (43-128 characters of [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~")
	verifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("generating code verifier: %w", err)
	}

	// Create S256 challenge: BASE64URL(SHA256(verifier))
	h := sha256.New()
	h.Write([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return &PKCEChallenge{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    "S256",
	}, nil
}

// generateCodeVerifier generates a cryptographically random code verifier
func generateCodeVerifier() (string, error) {
	// Use 32 bytes of randomness (will be base64url encoded to 43 characters)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Encode as base64url without padding
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
