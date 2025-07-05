package lookups

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"gonetmap/config"
	"gonetmap/model"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

var provider GeoIPProvider

// GeoIPProvider defines the interface for any geolocation service.
type GeoIPProvider interface {
	Lookup(ip string) (*model.GeoInfo, error)
	Name() string
}

// InitGeoIP initializes the GeoIP provider based on the application config.
func InitGeoIP(cfg *config.Config) error {
	switch cfg.GeoIP.Provider {
	case "maxmind":
		// Check if the database file exists.
		if _, err := os.Stat(cfg.GeoIP.DatabasePath); os.IsNotExist(err) {
			fmt.Printf("MaxMind DB not found at %s. Attempting to download...\n", cfg.GeoIP.DatabasePath)
			err := downloadAndExtractMaxMindDB(cfg.GeoIP.LicenseKey, cfg.GeoIP.DatabasePath)
			if err != nil {
				return fmt.Errorf("failed to download MaxMind database: %w", err)
			}
		}
		db, err := maxminddb.Open(cfg.GeoIP.DatabasePath)
		if err != nil {
			return fmt.Errorf("could not open maxmind db at %s: %w", cfg.GeoIP.DatabasePath, err)
		}
		provider = &MaxMindProvider{db: db}
	case "ip-api":
		provider = &IPAPIProvider{}
	default:
		return fmt.Errorf("unknown geoip provider '%s' specified in config.yaml. Use 'ip-api' or 'maxmind'", cfg.GeoIP.Provider)
	}
	fmt.Printf("✅ GeoIP provider initialized: %s\n", provider.Name())
	return nil
}

// downloadAndExtractMaxMindDB handles fetching and preparing the GeoLite2 database.
func downloadAndExtractMaxMindDB(licenseKey, targetPath string) error {
	if licenseKey == "" {
		return fmt.Errorf("license_key is not set in config.yaml. Please get a key from maxmind.com to enable automatic downloads")
	}

	// Construct the download URL
	url := fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz", licenseKey)

	fmt.Println("Downloading GeoLite2-City database...")
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to start download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", resp.Status)
	}

	// The downloaded file is a gzipped tarball, so we need to decompress and extract it.
	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	fmt.Println("Extracting database file...")
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// We are looking for the .mmdb file inside the archive.
		if strings.HasSuffix(header.Name, ".mmdb") {
			// Create the destination file.
			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("failed to create target file %s: %w", targetPath, err)
			}
			defer outFile.Close()

			// Copy the file contents from the archive to the destination file.
			if _, err := io.Copy(outFile, tarReader); err != nil {
				return fmt.Errorf("failed to copy file contents: %w", err)
			}

			fmt.Printf("✅ Successfully downloaded and extracted database to %s\n", targetPath)
			return nil // Success
		}
	}

	return fmt.Errorf("could not find a .mmdb file in the downloaded archive")
}

// LookupIP performs a geolocation lookup using the configured provider.
func LookupIP(ip string) (*model.GeoInfo, error) {
	if provider == nil {
		return nil, fmt.Errorf("geoip provider has not been initialized")
	}
	return provider.Lookup(ip)
}

// --- IP-API.com Provider (Web-based) ---

type IPAPIProvider struct{}

func (p *IPAPIProvider) Name() string {
	return "ip-api.com (web-based)"
}

func (p *IPAPIProvider) Lookup(ip string) (*model.GeoInfo, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s", ip)
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("could not fetch geo data for %s: %w", ip, err)
	}
	defer resp.Body.Close()

	var geoData struct {
		Status  string `json:"status"`
		Country string `json:"country"`
		City    string `json:"city"`
		ISP     string `json:"isp"`
		Message string `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&geoData); err != nil {
		return nil, fmt.Errorf("could not decode geo data for %s: %w", ip, err)
	}

	if geoData.Status == "fail" {
		if geoData.Message == "private range" {
			return nil, nil
		}
		return nil, fmt.Errorf("geolocation failed for %s: %s", ip, geoData.Message)
	}

	return &model.GeoInfo{
		Country: geoData.Country,
		City:    geoData.City,
		ISP:     geoData.ISP,
	}, nil
}

// --- MaxMind Provider (Offline Database) ---

type MaxMindProvider struct {
	db *maxminddb.Reader
}

type MaxMindRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		Names   map[string]string `maxminddb:"names"`
		IsoCode string            `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Traits struct {
		IsAnonymousProxy bool `maxminddb:"is_anonymous_proxy"`
	} `maxminddb:"traits"`
	ISP string `maxminddb:"isp"`
}

func (p *MaxMindProvider) Name() string {
	return "MaxMind DB (offline)"
}

func (p *MaxMindProvider) Lookup(ip string) (*model.GeoInfo, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address format: %s", ip)
	}

	var record MaxMindRecord
	err := p.db.Lookup(parsedIP, &record)
	if err != nil {
		return nil, err
	}

	if record.Country.IsoCode == "" && record.City.Names["en"] == "" {
		return nil, nil
	}

	return &model.GeoInfo{
		Country: record.Country.Names["en"],
		City:    record.City.Names["en"],
		ISP:     record.ISP,
	}, nil
}
