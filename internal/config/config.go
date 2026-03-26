package config

import (
	"os"
	"path/filepath"

	"github.com/krypsis-io/wick/internal/detect"
	"gopkg.in/yaml.v3"
)

// Config represents the merged configuration from all sources.
type Config struct {
	Style          string                 `yaml:"style"`
	CustomPatterns []detect.CustomPattern `yaml:"patterns"`
	Format         string                 `yaml:"format"`
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
	projectPath := findProjectConfig()
	if projectPath != "" {
		if err := loadFile(projectPath, cfg); err != nil {
			return nil, err
		}
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
