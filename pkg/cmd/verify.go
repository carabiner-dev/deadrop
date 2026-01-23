// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/carabiner-dev/command"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key type
	Kid string `json:"kid"` // Key ID
	Use string `json:"use"` // Public key use
	Alg string `json:"alg"` // Algorithm
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
}

var _ command.OptionsSet = (*VerifyOptions)(nil)

type VerifyOptions struct {
	TokenReadOptions
	ExpectedIssuer string
	SkipExpiry     bool
	SkipSignature  bool
}

var defaultVerifyOptions = VerifyOptions{}

func (vo *VerifyOptions) Validate() error {
	var errs = []error{
		vo.TokenReadOptions.Validate(),
	}
	return errors.Join(errs...)
}

func (vo *VerifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&vo.ExpectedIssuer, "issuer", "", "expected issuer URL (optional)")
	cmd.PersistentFlags().BoolVar(&vo.SkipExpiry, "skip-expiry", false, "skip expiration check")
	cmd.PersistentFlags().BoolVar(&vo.SkipSignature, "skip-signature", false, "skip signature verification")
}

func (vo *VerifyOptions) Config() *command.OptionsSetConfig {
	return nil
}

func AddVerify(parent *cobra.Command) {
	opts := defaultVerifyOptions

	cmd := &cobra.Command{
		Use:   "verify [token]",
		Short: "Verify a JWT token",
		Long: `Verify a JWT token.

This command decodes and validates a JWT token, checking:
- Signature validity (using the issuer's public keys)
- Expiration time (unless --skip-expiry is set)
- Standard claims (iss, sub, aud, exp, iat, etc.)

The token can be provided via --token flag or as the first argument.`,
		Example: `  # Verify a token from flag
  deadrop verify --token token.json

  # Verify a token from argument
  deadrop verify token.json

  # Verify without checking expiration
  deadrop verify token.json --skip-expiry

  # Verify with specific issuer
  deadrop verify token.json --issuer "https://auth.example.com"`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Get token from flag or first argument
			if opts.TokenPath == "" && len(args) > 0 {
				opts.TokenPath = args[0]
			}
			return opts.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Parse the token without verification first to extract claims and issuer
			parser := jwt.NewParser(jwt.WithoutClaimsValidation())
			tokendata, err := opts.ReadToken()
			if err != nil {
				return err
			}

			parsedToken, _, err := parser.ParseUnverified(tokendata, jwt.MapClaims{})
			if err != nil {
				return fmt.Errorf("failed to parse token: %w", err)
			}

			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			if !ok {
				return fmt.Errorf("failed to extract claims from token")
			}

			// Extract issuer for JWKS fetching
			issuer, ok := claims["iss"].(string)
			if !ok && !opts.SkipSignature {
				return fmt.Errorf("token does not contain 'iss' (issuer) claim, required for signature verification")
			}

			// Perform signature verification if not skipped
			var signatureValid bool
			var signatureError error

			if !opts.SkipSignature && issuer != "" {
				signatureValid, signatureError = verifySignature(opts.TokenPath, issuer)
			}

			// Print header
			fmt.Println("╭─────────────────────────────────────────────────────────────╮")
			fmt.Println("│                    JWT Token Verification                   │")
			fmt.Println("╰─────────────────────────────────────────────────────────────╯")
			fmt.Println()

			// Print algorithm
			fmt.Printf("Algorithm:  %s\n", parsedToken.Header["alg"])
			fmt.Printf("Type:       %s\n\n", parsedToken.Header["typ"])

			// Print standard claims
			fmt.Println("Standard Claims:")
			fmt.Println("─────────────────")

			if iss, ok := claims["iss"].(string); ok {
				fmt.Printf("  Issuer (iss):     %s\n", iss)
			}
			if sub, ok := claims["sub"].(string); ok {
				fmt.Printf("  Subject (sub):    %s\n", sub)
			}
			if aud, ok := claims["aud"]; ok {
				switch v := aud.(type) {
				case string:
					fmt.Printf("  Audience (aud):   %s\n", v)
				case []interface{}:
					fmt.Printf("  Audience (aud):   %v\n", v)
				}
			}

			// Print time-based claims
			if exp, ok := claims["exp"].(float64); ok {
				expTime := time.Unix(int64(exp), 0)
				fmt.Printf("  Expires (exp):    %s\n", expTime.Format(time.RFC3339))

				if !opts.SkipExpiry {
					if time.Now().After(expTime) {
						fmt.Printf("                    ❌ EXPIRED (expired %v ago)\n", time.Since(expTime).Round(time.Second))
					} else {
						fmt.Printf("                    ✅ Valid (expires in %v)\n", time.Until(expTime).Round(time.Second))
					}
				}
			}

			if iat, ok := claims["iat"].(float64); ok {
				iatTime := time.Unix(int64(iat), 0)
				fmt.Printf("  Issued At (iat):  %s\n", iatTime.Format(time.RFC3339))
				fmt.Printf("                    (issued %v ago)\n", time.Since(iatTime).Round(time.Second))
			}

			if nbf, ok := claims["nbf"].(float64); ok {
				nbfTime := time.Unix(int64(nbf), 0)
				fmt.Printf("  Not Before (nbf): %s\n", nbfTime.Format(time.RFC3339))
			}

			if jti, ok := claims["jti"].(string); ok {
				fmt.Printf("  JWT ID (jti):     %s\n", jti)
			}

			// Print custom claims (non-standard)
			standardClaims := map[string]bool{
				"iss": true, "sub": true, "aud": true, "exp": true,
				"iat": true, "nbf": true, "jti": true,
			}

			customClaims := make(map[string]interface{})
			for k, v := range claims {
				if !standardClaims[k] {
					customClaims[k] = v
				}
			}

			if len(customClaims) > 0 {
				fmt.Println()
				fmt.Println("Custom Claims:")
				fmt.Println("──────────────")
				customJSON, _ := json.MarshalIndent(customClaims, "  ", "  ")
				fmt.Printf("  %s\n", string(customJSON))
			}

			// Validation summary
			fmt.Println()
			fmt.Println("Validation:")
			fmt.Println("───────────")
			fmt.Println("  ✅ Token structure is valid")
			fmt.Println("  ✅ Claims can be decoded")

			// Check signature
			if !opts.SkipSignature {
				if signatureError != nil {
					fmt.Printf("  ❌ Signature verification FAILED: %v\n", signatureError)
					return fmt.Errorf("signature verification failed: %w", signatureError)
				} else if signatureValid {
					fmt.Println("  ✅ Signature is valid")
				}
			} else {
				fmt.Println("  ⚠️  Signature verification skipped")
			}

			// Check issuer if provided
			if opts.ExpectedIssuer != "" {
				if iss, ok := claims["iss"].(string); ok && iss == opts.ExpectedIssuer {
					fmt.Printf("  ✅ Issuer matches: %s\n", opts.ExpectedIssuer)
				} else {
					fmt.Printf("  ❌ Issuer mismatch: expected %s\n", opts.ExpectedIssuer)
					return fmt.Errorf("issuer validation failed")
				}
			}

			// Check expiration
			if !opts.SkipExpiry {
				if exp, ok := claims["exp"].(float64); ok {
					expTime := time.Unix(int64(exp), 0)
					if time.Now().After(expTime) {
						fmt.Println("  ❌ Token is EXPIRED")
						return fmt.Errorf("token is expired")
					} else {
						fmt.Println("  ✅ Token is not expired")
					}
				}
			} else {
				fmt.Println("  ⚠️  Expiration check skipped")
			}

			fmt.Println()
			fmt.Println("✅ Token verification completed successfully")

			return nil
		},
	}
	opts.AddFlags(cmd)
	parent.AddCommand(cmd)
}

// verifySignature verifies the JWT signature using the issuer's JWKS endpoint
func verifySignature(tokenString, issuer string) (bool, error) {
	// Fetch JWKS from the issuer
	jwksURL := issuer + "/.well-known/jwks.json"

	resp, err := http.Get(jwksURL) //nolint:gosec
	if err != nil {
		return false, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return false, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Parse the token to get the kid (key ID) from header
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsedToken, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return false, fmt.Errorf("failed to parse token header: %w", err)
	}

	kid, ok := parsedToken.Header["kid"].(string)
	if !ok {
		// If no kid, try the first key
		if len(jwks.Keys) == 0 {
			return false, fmt.Errorf("no keys found in JWKS")
		}
		kid = jwks.Keys[0].Kid
	}

	// Find the matching key
	var matchingKey *JWK
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == kid {
			matchingKey = &jwks.Keys[i]
			break
		}
	}

	if matchingKey == nil {
		return false, fmt.Errorf("key with kid=%q not found in JWKS", kid)
	}

	// Convert JWK to RSA public key
	publicKey, err := jwkToRSAPublicKey(matchingKey)
	if err != nil {
		return false, fmt.Errorf("failed to convert JWK to RSA public key: %w", err)
	}

	// Verify the token signature
	verifiedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return false, err
	}

	return verifiedToken.Valid, nil
}

// jwkToRSAPublicKey converts a JWK to an RSA public key
func jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s (only RSA is supported)", jwk.Kty)
	}

	// Decode the modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode the exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert bytes to big integers
	n := new(big.Int).SetBytes(nBytes)

	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e*256 + int(b)
	}

	// Create the RSA public key
	publicKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	return publicKey, nil
}
