// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package exchange

import (
	v1 "github.com/carabiner-dev/deadrop/api/v1"
)

const (
	// RFC 8693 constants
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
)

// Type aliases for the proto types - exported for use by other packages
type (
	ExchangeRequest  = v1.ExchangeRequest
	ExchangeResponse = v1.ExchangeResponse
	ErrorResponse    = v1.ErrorResponse
)
