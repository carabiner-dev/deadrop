// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/carabiner-dev/deadrop/pkg/client/credentials"
)

// ServerOptions is an alias for credentials.ServerOptions.
type ServerOptions = credentials.ServerOptions

// LoginOpts is an alias for credentials.LoginOptions.
type LoginOpts = credentials.LoginOptions

var (
	defaultServerOptions = *credentials.NewServerOptions()
	defaultLoginOpts     = *credentials.NewLoginOptions()
)
