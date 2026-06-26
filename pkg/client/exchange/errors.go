// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package exchange

import "errors"

// ErrAuthRequired indicates that a request cannot be authenticated because the
// caller must (re-)authenticate: there are no usable credentials, or the
// identity that was presented was rejected or has expired. It is wrapped into
// the returned error (not returned bare), so callers should detect it with
// errors.Is and prompt the user to log in again rather than surfacing the raw
// token-exchange failure.
var ErrAuthRequired = errors.New("authentication required")

// oauthAuthErrorCodes are the OAuth 2.0 / RFC 8693 token-exchange error codes
// that mean the presented subject identity could not be authenticated — i.e.
// the user needs to log in again — as opposed to a malformed request or a
// transient server-side fault. When the exchange server returns one of these,
// the failure is classified as ErrAuthRequired.
var oauthAuthErrorCodes = map[string]bool{
	"invalid_token":       true, // subject token is invalid or expired
	"invalid_grant":       true, // grant (the identity) was rejected
	"invalid_client":      true,
	"unauthorized_client": true,
	"access_denied":       true,
	"token_expired":       true,
}

// isAuthErrorCode reports whether an OAuth error code denotes a failure the user
// can resolve by re-authenticating.
func isAuthErrorCode(code string) bool {
	return oauthAuthErrorCodes[code]
}
