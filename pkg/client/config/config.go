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
	// Server Configuration
	ServerURL string `yaml:"server_url"` // deadrop server for token exchange
	LoginURL  string `yaml:"login_url"`  // login service URL (e.g., https://login.carabiner.dev)

	// Authentication
	Provider string `yaml:"provider"` // OAuth provider hint (e.g., "google")

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
