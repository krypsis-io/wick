// Package config handles loading and merging wick configuration files.
package config

import (
	"os"
	"path/filepath"

	"github.com/krypsis-io/wick/detect"
	"gopkg.in/yaml.v3"
)

// Config represents the merged configuration from all sources.
type Config struct {
	Style          string                 `yaml:"style"`
	CustomPatterns []detect.CustomPattern `yaml:"patterns"`
	Format         string                 `yaml:"format"`
	Allowlist      []detect.AllowlistEntry `yaml:"allowlist"`
	Blocklist      []BlocklistEntry        `yaml:"blocklist"`
}

// BlocklistEntry defines a pattern that is always redacted, even if not matched
// by built-in rules. It is compiled as a custom detection pattern.
type BlocklistEntry struct {
	Pattern  string `yaml:"pattern"`
	Category string `yaml:"category,omitempty"`
	Reason   string `yaml:"reason,omitempty"`
}

// Load reads configuration from global (~/.config/wick/config.yaml) and
// project (.wick.yaml) config files, merging them with project overriding global.
func Load() (*Config, error) {
	cfg := &Config{
		Style: "redacted",
	}

	// Global config.
	home, err := os.UserHomeDir()
	if err == nil {
		globalPath := filepath.Join(home, ".config", "wick", "config.yaml")
		if err := loadFile(globalPath, cfg); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}

	// Project config (walk up from cwd to find .wick.yaml).
	// Unmarshal into a temp struct and merge so slices are appended, not replaced.
	projectPath := findProjectConfig()
	if projectPath != "" {
		var proj Config
		if err := loadFile(projectPath, &proj); err != nil {
			return nil, err
		}
		if proj.Style != "" {
			cfg.Style = proj.Style
		}
		if proj.Format != "" {
			cfg.Format = proj.Format
		}
		cfg.CustomPatterns = append(cfg.CustomPatterns, proj.CustomPatterns...)
		cfg.Allowlist = append(cfg.Allowlist, proj.Allowlist...)
		cfg.Blocklist = append(cfg.Blocklist, proj.Blocklist...)
	}

	return cfg, nil
}

func loadFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, cfg)
}

func findProjectConfig() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		candidate := filepath.Join(dir, ".wick.yaml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}
