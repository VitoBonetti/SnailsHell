package maclookup

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// LookupVendor queries macvendors.com for the vendor of a given MAC address.
func LookupVendor(mac string) (string, error) {
	// The API is simple: just a GET request to the URL with the MAC.
	url := fmt.Sprintf("https://api.macvendors.com/%s", mac)

	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to make request to MAC vendor API: %w", err)
	}
	defer resp.Body.Close()

	// Handle cases where the vendor is not found (404)
	if resp.StatusCode == http.StatusNotFound {
		return "Unknown Vendor", nil
	}
	// Handle other potential errors
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
	}

	// Read the vendor name from the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read MAC vendor response body: %w", err)
	}

	return string(body), nil
}
