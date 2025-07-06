package webenum

import (
	"SnailsHell/model"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ProbeWebServer sends various HTTP requests to a web server and returns the responses.
func ProbeWebServer(host *model.Host) {
	for portID, port := range host.Ports {
		if !isWebPort(portID, port.Service) {
			continue
		}

		// Determine the protocol (http or https)
		protocol := "http"
		if portID == 443 || portID == 8443 || strings.Contains(port.Service, "ssl") || strings.Contains(port.Service, "https") {
			protocol = "https"
		}

		// Create a custom HTTP client that ignores TLS certificate errors
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

		for _, method := range []string{"GET", "POST", "OPTIONS"} {
			var ip string
			for hostIP := range host.IPv4Addresses {
				ip = hostIP
				break
			}
			if ip == "" {
				continue
			}
			url := fmt.Sprintf("%s://%s:%d", protocol, ip, portID)

			req, err := http.NewRequest(method, url, nil)
			if err != nil {
				fmt.Printf("Error creating request for %s: %v\n", url, err)
				continue
			}

			// Set a user-agent
			req.Header.Set("User-Agent", "SnailsHell-Scanner/1.0")

			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf("Error performing %s request to %s: %v\n", method, url, err)
				continue
			}
			defer resp.Body.Close()

			// Create and populate the WebResponse struct
			webResponse := model.WebResponse{
				PortID:     portID,
				Method:     method,
				StatusCode: resp.StatusCode,
				Headers:    make(map[string]string),
			}
			for key, values := range resp.Header {
				webResponse.Headers[key] = strings.Join(values, ", ")
			}

			// Add the response to the host
			if host.WebResponses == nil {
				host.WebResponses = make([]model.WebResponse, 0)
			}
			host.WebResponses = append(host.WebResponses, webResponse)
		}
	}
}

// isWebPort checks if a port is likely a web server.
func isWebPort(portID int, service string) bool {
	webPorts := []int{80, 81, 88, 443, 8000, 8008, 8080, 8443, 9080, 9443}
	for _, p := range webPorts {
		if portID == p {
			return true
		}
	}

	webServices := []string{"http", "https", "www", "ssl/http", "http-proxy"}
	for _, s := range webServices {
		if strings.Contains(service, s) {
			return true
		}
	}

	return false
}
