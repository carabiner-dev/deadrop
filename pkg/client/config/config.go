// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/adrg/xdg"
	"gopkg.in/yaml.v3"
)

// Config represents client configuration
type Config struct {
	// OAuth Configuration (for direct OAuth flows, not used with login service)
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Provider     string   `yaml:"provider"` // "google", "microsoft"
	Scopes       []string `yaml:"scopes"`

	// Server Configuration
	ServerURL string `yaml:"server_url"` // deadrop server for token exchange
	LoginURL  string `yaml:"login_url"`  // login service URL (e.g., https://login.carabiner.dev)

	// Token Configuration
	Audience []string `yaml:"audience"`

	// Storage paths (auto-populated from XDG)
	DataDir   string `yaml:"-"`
	ConfigDir string `yaml:"-"`
}

// Load loads configuration from a file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Populate XDG directories
	cfg.DataDir = filepath.Join(xdg.DataHome, "deadrop")
	cfg.ConfigDir = filepath.Join(xdg.ConfigHome, "deadrop")

	return &cfg, nil
}

// LoadWithDefaults loads config from default location or returns defaults
func LoadWithDefaults() (*Config, error) {
	configPath := filepath.Join(xdg.ConfigHome, "deadrop", "config.yaml")

	// Try to load from file
	cfg, err := Load(configPath)
	if err != nil {
		// If file doesn't exist, return defaults
		if os.IsNotExist(err) {
			cfg = &Config{
				Provider: "google",
				Scopes:   []string{"openid", "email", "profile"},
			}
		} else {
			return nil, err
		}
	}

	// Set default login URL if not configured
	if cfg.LoginURL == "" {
		cfg.LoginURL = "https://login.carabiner.dev"
	}

	// Apply environment variable overrides
	cfg.ApplyEnvVars()

	// Populate XDG directories if not set
	if cfg.DataDir == "" {
		cfg.DataDir = filepath.Join(xdg.DataHome, "deadrop")
	}
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = filepath.Join(xdg.ConfigHome, "deadrop")
	}

	return cfg, nil
}

// ApplyEnvVars applies environment variable overrides
func (c *Config) ApplyEnvVars() {
	if v := os.Getenv("DEADROP_CLIENT_ID"); v != "" {
		c.ClientID = v
	}
	if v := os.Getenv("DEADROP_CLIENT_SECRET"); v != "" {
		c.ClientSecret = v
	}
	if v := os.Getenv("DEADROP_SERVER"); v != "" {
		c.ServerURL = v
	}
	if v := os.Getenv("DEADROP_LOGIN_URL"); v != "" {
		c.LoginURL = v
	}
	if v := os.Getenv("DEADROP_PROVIDER"); v != "" {
		c.Provider = v
	}
	if v := os.Getenv("DEADROP_AUDIENCE"); v != "" {
		// Comma-separated audiences
		audiences := strings.Split(v, ",")
		for i, aud := range audiences {
			audiences[i] = strings.TrimSpace(aud)
		}
		c.Audience = audiences
	}
}

// ApplyFlags applies command-line flag overrides
func (c *Config) ApplyFlags(flags map[string]interface{}) {
	if v, ok := flags["client-id"].(string); ok && v != "" {
		c.ClientID = v
	}
	if v, ok := flags["client-secret"].(string); ok && v != "" {
		c.ClientSecret = v
	}
	if v, ok := flags["server"].(string); ok && v != "" {
		c.ServerURL = v
	}
	if v, ok := flags["provider"].(string); ok && v != "" {
		c.Provider = v
	}
	if v, ok := flags["audience"].([]string); ok && len(v) > 0 {
		c.Audience = v
	}
}

// GetIssuerURL returns the issuer URL for the configured provider
func (c *Config) GetIssuerURL() string {
	defaults := GetProviderDefaults(c.Provider)
	return defaults.IssuerURL
}

// GetAuthURL returns the authorization URL for the configured provider
func (c *Config) GetAuthURL() string {
	defaults := GetProviderDefaults(c.Provider)
	return defaults.AuthURL
}

// GetTokenURL returns the token URL for the configured provider
func (c *Config) GetTokenURL() string {
	defaults := GetProviderDefaults(c.Provider)
	return defaults.TokenURL
}

// GetScopes returns the scopes to use, falling back to provider defaults
func (c *Config) GetScopes() []string {
	if len(c.Scopes) > 0 {
		return c.Scopes
	}
	defaults := GetProviderDefaults(c.Provider)
	return defaults.Scopes
}

// Validate checks that required configuration is present
func (c *Config) Validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("client ID is required (set via --client-id flag or DEADROP_CLIENT_ID env var)")
	}
	if c.ServerURL == "" {
		return fmt.Errorf("server URL is required (set via --server flag or DEADROP_SERVER env var)")
	}
	if len(c.Audience) == 0 {
		return fmt.Errorf("audience is required (set via --audience flag or DEADROP_AUDIENCE env var)")
	}
	return nil
}
