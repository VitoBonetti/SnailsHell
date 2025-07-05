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
	// NEW: GeoIP struct
	GeoIP struct {
		Provider     string `yaml:"provider"`
		DatabasePath string `yaml:"database_path"`
	} `yaml:"geoip"`
}

// Cfg is a global variable that will hold the loaded configuration.
var Cfg *Config

// LoadConfig loads the configuration from a file or creates a default one if it doesn't exist.
func LoadConfig() error {
	Cfg = &Config{}
	configPath := "config.yaml"

	// Check if the config file exists.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Println("No config.yaml found. Creating a default one.")
		return createDefaultConfig(configPath)
	}

	// If it exists, read it.
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("could not read config file %s: %w", configPath, err)
	}

	// Unmarshal the YAML data into our Config struct.
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
		// NEW: Default GeoIP settings
		GeoIP: struct {
			Provider     string `yaml:"provider"`
			DatabasePath string `yaml:"database_path"`
		}{
			Provider:     "ip-api",
			DatabasePath: "./GeoLite2-City.mmdb",
		},
	}

	// Marshal the default config struct into YAML format.
	data, err := yaml.Marshal(&defaultConfig)
	if err != nil {
		return fmt.Errorf("could not marshal default config: %w", err)
	}

	// Write the YAML data to the file.
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("could not write default config file: %w", err)
	}

	// Set the global Cfg variable to the default config so the app can use it immediately.
	Cfg = &defaultConfig

	return nil
}
