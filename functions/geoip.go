package functions

import (
	"encoding/json"
	"fmt"
	"gonetmap/model"
	"net"
	"net/http"
	"time"
)

// apiBaseURL is the base URL for the ip-api.com service.
const apiBaseURL = "http://ip-api.com/json/"

// apiResponse matches the JSON structure returned by ip-api.com
type apiResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"` // Used for error messages from the API
	Country string `json:"country"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
}

// isLookupableIP checks if an IP address is a global unicast address that
// we should perform a lookup on.
func isLookupableIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// We only want to look up global unicast addresses.
	// This excludes private, loopback, multicast, etc.
	return ip.IsGlobalUnicast()
}

// LookupIP queries the ip-api.com service for information about a public IP.
func LookupIP(ipStr string) (*model.GeoInfo, error) {
	ip := net.ParseIP(ipStr)
	// --- THE IMPROVEMENT IS HERE ---
	// Use the helper to ensure we only query valid public IPs.
	if !isLookupableIP(ip) {
		return nil, nil // Not an error, just nothing to do
	}

	url := fmt.Sprintf("%s%s", apiBaseURL, ipStr)

	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to geo API: %w", err)
	}
	defer resp.Body.Close()

	var result apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode geo API response: %w", err)
	}

	if result.Status != "success" {
		return nil, nil
	}

	return &model.GeoInfo{
		Country: result.Country,
		City:    result.City,
		ISP:     result.ISP,
	}, nil
}
