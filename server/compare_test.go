package server

import (
	"SnailsHell/model"
	"SnailsHell/storage"
	"testing"
)

// setupTestDB is a helper function that initializes a temporary, in-memory SQLite database for testing.
func setupTestDB(t *testing.T) {
	// The ":memory:" filename tells SQLite to create a database in memory.
	// "cache=shared" is important to allow multiple connections to the same in-memory DB.
	if err := storage.InitDB("file::memory:?cache=shared"); err != nil {
		t.Fatalf("Failed to initialize in-memory database: %v", err)
	}
}

// TestCompareCampaigns tests the core logic of diffing two campaigns.
func TestCompareCampaigns(t *testing.T) {
	setupTestDB(t)

	// --- 1. Create Base Campaign Data ---
	baseCampaignID, _ := storage.GetOrCreateCampaign("Base Campaign")
	baseMap := model.NewNetworkMap()
	// Host A: Will be changed
	hostA_base := model.NewHost("00:00:00:AA:AA:AA")
	hostA_base.Status = "up"
	hostA_base.Ports[80] = model.Port{ID: 80, Protocol: "tcp", State: "open"}
	baseMap.Hosts[hostA_base.MACAddress] = hostA_base
	// Host B: Will be missing
	hostB_base := model.NewHost("00:00:00:BB:BB:BB")
	baseMap.Hosts[hostB_base.MACAddress] = hostB_base

	if err := storage.SaveScanResults(baseCampaignID, baseMap, model.NewPcapSummary()); err != nil {
		t.Fatalf("Failed to save base campaign data: %v", err)
	}

	// --- 2. Create Comparison Campaign Data ---
	compCampaignID, _ := storage.GetOrCreateCampaign("Comparison Campaign")
	compMap := model.NewNetworkMap()
	// Host A: Changed (port 443 instead of 80)
	hostA_comp := model.NewHost("00:00:00:AA:AA:AA")
	hostA_comp.Status = "up"
	hostA_comp.Ports[443] = model.Port{ID: 443, Protocol: "tcp", State: "open"}
	compMap.Hosts[hostA_comp.MACAddress] = hostA_comp
	// Host C: Is new
	hostC_comp := model.NewHost("00:00:00:CC:CC:CC")
	compMap.Hosts[hostC_comp.MACAddress] = hostC_comp

	if err := storage.SaveScanResults(compCampaignID, compMap, model.NewPcapSummary()); err != nil {
		t.Fatalf("Failed to save comparison campaign data: %v", err)
	}

	// --- 3. Run the comparison ---
	result, err := CompareCampaigns(baseCampaignID, compCampaignID)
	if err != nil {
		t.Fatalf("CompareCampaigns failed: %v", err)
	}

	// --- 4. Assert the results ---
	if len(result.NewHosts) != 1 {
		t.Errorf("Expected 1 new host, but got %d", len(result.NewHosts))
	} else if result.NewHosts[0].MACAddress != "00:00:00:CC:CC:CC" {
		t.Errorf("Incorrect new host found: got %s", result.NewHosts[0].MACAddress)
	}

	if len(result.MissingHosts) != 1 {
		t.Errorf("Expected 1 missing host, but got %d", len(result.MissingHosts))
	} else if result.MissingHosts[0].MACAddress != "00:00:00:BB:BB:BB" {
		t.Errorf("Incorrect missing host found: got %s", result.MissingHosts[0].MACAddress)
	}

	if len(result.ChangedHosts) != 1 {
		t.Errorf("Expected 1 changed host, but got %d", len(result.ChangedHosts))
	} else {
		change := result.ChangedHosts[0]
		if change.Host.MACAddress != "00:00:00:AA:AA:AA" {
			t.Errorf("Incorrect changed host found: got %s", change.Host.MACAddress)
		}
		if len(change.NewPorts) != 1 || change.NewPorts[0].ID != 443 {
			t.Error("Expected to find new port 443 on changed host")
		}
		if len(change.RemovedPorts) != 1 || change.RemovedPorts[0].ID != 80 {
			t.Error("Expected to find removed port 80 on changed host")
		}
	}
}
