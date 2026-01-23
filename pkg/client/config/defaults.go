// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package config

// ProviderConfig holds OAuth provider-specific defaults
type ProviderConfig struct {
	IssuerURL string
	AuthURL   string
	TokenURL  string
	Scopes    []string
}

// Provider defaults for supported OAuth providers
var (
	GoogleDefaults = ProviderConfig{
		IssuerURL: "https://accounts.google.com",
		AuthURL:   "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:  "https://oauth2.googleapis.com/token",
		Scopes:    []string{"openid", "email", "profile"},
	}

	MicrosoftDefaults = ProviderConfig{
		IssuerURL: "https://login.microsoftonline.com/common/v2.0",
		AuthURL:   "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		Scopes:    []string{"openid", "email", "profile"},
	}

	GitHubDefaults = ProviderConfig{
		IssuerURL: "https://token.actions.githubusercontent.com",
		AuthURL:   "", // GitHub Actions doesn't use browser OAuth
		TokenURL:  "", // Token retrieved via API
		Scopes:    []string{},
	}
)

// GetProviderDefaults returns the default configuration for a provider
func GetProviderDefaults(provider string) *ProviderConfig {
	switch provider {
	case "google":
		return &GoogleDefaults
	case "microsoft":
		return &MicrosoftDefaults
	case "github":
		return &GitHubDefaults
	default:
		return &GoogleDefaults // Default to Google
	}
}
