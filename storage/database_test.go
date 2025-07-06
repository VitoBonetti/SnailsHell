package storage

import (
	"SnailsHell/model"
	"bytes"
	"testing"
	"time"
)

// setupTestDB is a helper function that initializes a temporary, in-memory SQLite database for testing.
func setupTestDB(t *testing.T) {
	// The ":memory:" filename tells SQLite to create a database in memory.
	// "cache=shared" is important to allow multiple connections to the same in-memory DB.
	if err := InitDB("file::memory:?cache=shared"); err != nil {
		t.Fatalf("Failed to initialize in-memory database: %v", err)
	}
}

// TestCampaigns tests the creation and deletion of campaigns.
func TestCampaigns(t *testing.T) {
	setupTestDB(t)

	t.Run("CreateAndGetCampaign", func(t *testing.T) {
		campaignName := "Test Campaign 1"
		id1, err := GetOrCreateCampaign(campaignName)
		if err != nil {
			t.Fatalf("GetOrCreateCampaign failed for new campaign: %v", err)
		}
		if id1 == 0 {
			t.Fatal("Expected a non-zero ID for a new campaign")
		}

		id2, err := GetOrCreateCampaign(campaignName)
		if err != nil {
			t.Fatalf("GetOrCreateCampaign failed for existing campaign: %v", err)
		}
		if id1 != id2 {
			t.Errorf("Expected the same ID for an existing campaign, got %d, want %d", id2, id1)
		}
	})

	t.Run("DeleteCampaign", func(t *testing.T) {
		campaignName := "Campaign To Delete"
		id, err := GetOrCreateCampaign(campaignName)
		if err != nil {
			t.Fatalf("Failed to create campaign for deletion test: %v", err)
		}

		if err := DeleteCampaignByID(id); err != nil {
			t.Fatalf("DeleteCampaignByID failed: %v", err)
		}

		_, err = GetCampaignByID(id)
		if err == nil {
			t.Error("Expected an error when getting a deleted campaign, but got nil")
		}
	})
}

// TestSaveAndGetHost tests the full lifecycle of saving and retrieving a complex host object.
func TestSaveAndGetHost(t *testing.T) {
	setupTestDB(t)

	campaignID, err := GetOrCreateCampaign("Host Save Test")
	if err != nil {
		t.Fatalf("Failed to create campaign: %v", err)
	}

	mac := "AA:BB:CC:DD:EE:FF"
	hostToSave := model.NewHost(mac)
	hostToSave.Status = "up"
	hostToSave.IPv4Addresses["192.168.1.100"] = true
	hostToSave.Fingerprint.OperatingSystem = "Linux 5.4"
	hostToSave.Fingerprint.Vendor = "TestVendor"
	hostToSave.Ports[80] = model.Port{ID: 80, Protocol: "tcp", State: "open", Service: "http"}
	hostToSave.Ports[443] = model.Port{ID: 443, Protocol: "tcp", State: "open", Service: "https"}
	hostToSave.Findings[model.CriticalFinding] = []model.Vulnerability{
		{CVE: "CVE-2025-1234", Description: "A critical issue", PortID: 443, Category: model.CriticalFinding},
	}

	networkMap := model.NewNetworkMap()
	networkMap.Hosts[mac] = hostToSave
	summary := model.NewPcapSummary()

	if err := SaveScanResults(campaignID, networkMap, summary); err != nil {
		t.Fatalf("SaveScanResults failed: %v", err)
	}

	var hostDBID int64
	err = DB.QueryRow("SELECT id FROM hosts WHERE mac_address = ?", mac).Scan(&hostDBID)
	if err != nil {
		t.Fatalf("Could not get host DB ID for verification: %v", err)
	}

	retrievedHost, err := GetHostByID(hostDBID, campaignID)
	if err != nil {
		t.Fatalf("GetHostByID failed: %v", err)
	}

	if retrievedHost.MACAddress != mac {
		t.Errorf("MAC address mismatch: got %s, want %s", retrievedHost.MACAddress, mac)
	}
	if retrievedHost.Status != "up" {
		t.Errorf("Status mismatch: got %s, want %s", retrievedHost.Status, "up")
	}
	if !retrievedHost.IPv4Addresses["192.168.1.100"] {
		t.Error("Expected IP address 192.168.1.100 to be present")
	}
	if retrievedHost.Fingerprint.OperatingSystem != "Linux 5.4" {
		t.Errorf("OS mismatch: got %s, want %s", retrievedHost.Fingerprint.OperatingSystem, "Linux 5.4")
	}
	if len(retrievedHost.Ports) != 2 {
		t.Errorf("Expected 2 ports, but got %d", len(retrievedHost.Ports))
	}
	if retrievedHost.Ports[80].Service != "http" {
		t.Errorf("Port 80 service mismatch: got %s, want http", retrievedHost.Ports[80].Service)
	}

	if len(retrievedHost.Findings[model.CriticalFinding]) != 1 {
		t.Fatalf("Expected 1 critical finding, but got %d", len(retrievedHost.Findings[model.CriticalFinding]))
	}
	if retrievedHost.Findings[model.CriticalFinding][0].CVE != "CVE-2025-1234" {
		t.Errorf("Finding CVE mismatch: got %s, want CVE-2025-1234", retrievedHost.Findings[model.CriticalFinding][0].CVE)
	}
}

// TestSaveAndGetWebResponse verifies that web server response headers are correctly stored and retrieved.
func TestSaveAndGetWebResponse(t *testing.T) {
	setupTestDB(t)

	campaignID, _ := GetOrCreateCampaign("Web Response Test")
	networkMap, summary := model.NewNetworkMap(), model.NewPcapSummary()

	// Create a host with a web response
	host := model.NewHost("11:22:33:44:55:66")
	host.Ports[8080] = model.Port{ID: 8080, Protocol: "tcp", State: "open", Service: "http"}
	host.WebResponses = []model.WebResponse{
		{
			PortID:     8080,
			Method:     "GET",
			StatusCode: 200,
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Server":       "TestServer/1.0",
			},
		},
	}
	networkMap.Hosts[host.MACAddress] = host

	if err := SaveScanResults(campaignID, networkMap, summary); err != nil {
		t.Fatalf("SaveScanResults failed: %v", err)
	}

	// Retrieve the host and check the web response
	var hostDBID int64
	DB.QueryRow("SELECT id FROM hosts WHERE mac_address = ?", host.MACAddress).Scan(&hostDBID)

	retrievedHost, err := GetHostByID(hostDBID, campaignID)
	if err != nil {
		t.Fatalf("GetHostByID failed: %v", err)
	}

	if len(retrievedHost.WebResponses) != 1 {
		t.Fatalf("Expected 1 web response, but got %d", len(retrievedHost.WebResponses))
	}

	resp := retrievedHost.WebResponses[0]
	if resp.StatusCode != 200 {
		t.Errorf("Incorrect status code: got %d, want 200", resp.StatusCode)
	}
	if resp.Headers["Server"] != "TestServer/1.0" {
		t.Errorf("Incorrect server header: got %s, want TestServer/1.0", resp.Headers["Server"])
	}
}

// TestSaveAndGetScreenshot verifies that screenshot image data is correctly stored and retrieved.
func TestSaveAndGetScreenshot(t *testing.T) {
	setupTestDB(t)

	campaignID, _ := GetOrCreateCampaign("Screenshot Test")
	networkMap, summary := model.NewNetworkMap(), model.NewPcapSummary()

	// Create a host with a screenshot
	host := model.NewHost("77:88:99:AA:BB:CC")
	host.Ports[443] = model.Port{ID: 443, Protocol: "tcp", State: "open", Service: "https"}
	fakeImageData := []byte("this-is-a-fake-png")
	host.Screenshots = []model.Screenshot{
		{
			PortID:      443,
			ImageData:   fakeImageData,
			CaptureTime: time.Now(),
		},
	}
	networkMap.Hosts[host.MACAddress] = host

	if err := SaveScanResults(campaignID, networkMap, summary); err != nil {
		t.Fatalf("SaveScanResults failed: %v", err)
	}

	// Retrieve the host and check the screenshot
	var hostDBID int64
	DB.QueryRow("SELECT id FROM hosts WHERE mac_address = ?", host.MACAddress).Scan(&hostDBID)

	retrievedHost, err := GetHostByID(hostDBID, campaignID)
	if err != nil {
		t.Fatalf("GetHostByID failed: %v", err)
	}

	if len(retrievedHost.Screenshots) != 1 {
		t.Fatalf("Expected 1 screenshot, but got %d", len(retrievedHost.Screenshots))
	}

	sc := retrievedHost.Screenshots[0]
	if !bytes.Equal(sc.ImageData, fakeImageData) {
		t.Error("Screenshot image data does not match")
	}

	// Also test the standalone GetScreenshotByID function
	retrievedImageData, err := GetScreenshotByID(sc.ID)
	if err != nil {
		t.Fatalf("GetScreenshotByID failed: %v", err)
	}
	if !bytes.Equal(retrievedImageData, fakeImageData) {
		t.Error("GetScreenshotByID returned incorrect image data")
	}
}
