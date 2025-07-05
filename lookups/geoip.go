package lookups

import (
	"encoding/json"
	"fmt"
	"gonetmap/model"
	"net/http"
	"time"
)

// LookupIP performs a geolocation lookup for a given IP address.
func LookupIP(ip string) (*model.GeoInfo, error) {
	// Use a free, public API for geolocation.
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
		return nil, fmt.Errorf("geolocation failed for %s: %s", ip, geoData.Message)
	}

	return &model.GeoInfo{
		Country: geoData.Country,
		City:    geoData.City,
		ISP:     geoData.ISP,
	}, nil
}
