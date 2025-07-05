package lookups

import (
	"encoding/json"
	"fmt"
	"gonetmap/config"
	"gonetmap/model"
	"net"
	"net/http"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// provider is the global instance of the configured GeoIP provider.
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
		db, err := maxminddb.Open(cfg.GeoIP.DatabasePath)
		if err != nil {
			return fmt.Errorf("could not open maxmind db at %s: %w. Make sure you have downloaded it from the MaxMind website", cfg.GeoIP.DatabasePath, err)
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
		// Private range IPs will fail, which is normal.
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

// MaxMindRecord is the structure that matches the GeoLite2-City database.
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

	// If the IP is not found in the database, the record will be empty.
	if record.Country.IsoCode == "" && record.City.Names["en"] == "" {
		return nil, nil // Not found is not an error
	}

	return &model.GeoInfo{
		Country: record.Country.Names["en"],
		City:    record.City.Names["en"],
		ISP:     record.ISP,
	}, nil
}
