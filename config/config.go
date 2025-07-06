package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// SSHCredentials holds a username and password for SSH.
type SSHCredentials struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

// Config holds all the configuration for the application.
type Config struct {
	Application struct {
		Name            string `yaml:"name"`
		Version         string `yaml:"version"`
		GithubURL       string `yaml:"github_url"`
		UpdateAvailable bool   `yaml:"-"` // Won't be read/written to config.yaml
		LatestVersion   string `yaml:"-"` // Won't be read/written to config.yaml
	} `yaml:"application"`
	Database struct {
		Path string `yaml:"path"`
	} `yaml:"database"`
	DefaultPaths struct {
		DataDir string `yaml:"data_dir"`
	} `yaml:"default_paths"`
	GeoIP struct {
		Provider     string `yaml:"provider"`
		DatabasePath string `yaml:"database_path"`
		LicenseKey   string `yaml:"license_key"`
	} `yaml:"geoip"`
	Nmap struct {
		Path        string   `yaml:"path"`
		DefaultArgs []string `yaml:"default_args"`
	} `yaml:"nmap"`
	Credentials struct {
		SSH []SSHCredentials `yaml:"ssh"`
	} `yaml:"credentials"`
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

	// Ensure default credentials are set if the section is missing
	if Cfg.Credentials.SSH == nil {
		Cfg.Credentials.SSH = []SSHCredentials{
			{User: "root", Password: "root"},
			{User: "root", Password: ""},
		}
	}

	fmt.Println("✅ Configuration loaded from config.yaml.")
	return nil
}

// createDefaultConfig creates a default config.yaml file with sensible defaults.
func createDefaultConfig(path string) error {
	defaultConfig := Config{
		Application: struct {
			Name            string `yaml:"name"`
			Version         string `yaml:"version"`
			GithubURL       string `yaml:"github_url"`
			UpdateAvailable bool   `yaml:"-"`
			LatestVersion   string `yaml:"-"`
		}{
			Name:      "SnailsHell",
			Version:   "1.2.0",
			GithubURL: "https://github.com/VitoBonetti/SnailsHell",
		},
		Database: struct {
			Path string `yaml:"path"`
		}{
			Path: "snailshell.db",
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
			LicenseKey:   "",
		},
		Nmap: struct {
			Path        string   `yaml:"path"`
			DefaultArgs []string `yaml:"default_args"`
		}{
			Path:        "",
			DefaultArgs: []string{"-Pn", "-O", "-sV", "--script", "vuln"},
		},
		Credentials: struct {
			SSH []SSHCredentials `yaml:"ssh"`
		}{
			SSH: []SSHCredentials{
				{User: "root", Password: "root"},
				{User: "root", Password: ""},
			},
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
