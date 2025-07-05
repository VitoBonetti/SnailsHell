package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Config holds all the configuration for the application.
type Config struct {
	Database struct {
		Path string `yaml:"path"`
	} `yaml:"database"`
	DefaultPaths struct {
		DataDir string `yaml:"data_dir"`
	} `yaml:"default_paths"`
	GeoIP struct {
		Provider     string `yaml:"provider"`
		DatabasePath string `yaml:"database_path"`
		// NEW: License key for MaxMind downloads.
		LicenseKey string `yaml:"license_key"`
	} `yaml:"geoip"`
}

// Cfg is a global variable that will hold the loaded configuration.
var Cfg *Config

// LoadConfig loads the configuration from a file or creates a default one if it doesn't exist.
func LoadConfig() error {
	Cfg = &Config{}
	configPath := "config.yaml"

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Println("No config.yaml found. Creating a default one.")
		return createDefaultConfig(configPath)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("could not read config file %s: %w", configPath, err)
	}

	if err := yaml.Unmarshal(data, Cfg); err != nil {
		return fmt.Errorf("could not parse config file %s: %w", configPath, err)
	}

	fmt.Println("✅ Configuration loaded from config.yaml.")
	return nil
}

// createDefaultConfig creates a default config.yaml file with sensible defaults.
func createDefaultConfig(path string) error {
	defaultConfig := Config{
		Database: struct {
			Path string `yaml:"path"`
		}{
			Path: "gonetmap.db",
		},
		DefaultPaths: struct {
			DataDir string `yaml:"data_dir"`
		}{
			DataDir: "./data",
		},
		GeoIP: struct {
			Provider     string `yaml:"provider"`
			DatabasePath string `yaml:"database_path"`
			LicenseKey   string `yaml:"license_key"`
		}{
			Provider:     "ip-api",
			DatabasePath: "./GeoLite2-City.mmdb",
			// Users must fill this in themselves.
			LicenseKey: "",
		},
	}

	data, err := yaml.Marshal(&defaultConfig)
	if err != nil {
		return fmt.Errorf("could not marshal default config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("could not write default config file: %w", err)
	}

	Cfg = &defaultConfig

	return nil
}
