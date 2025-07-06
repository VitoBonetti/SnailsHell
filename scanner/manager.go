package scanner

import (
	"context"
	"fmt"
	"gonetmap/livecapture"
	"gonetmap/model"
	"gonetmap/processing"
	"gonetmap/storage"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ScanManager holds the state of the currently active scan.
type ScanManager struct {
	mu         sync.Mutex
	IsScanning bool
	Status     string
	cancelFunc context.CancelFunc
}

// Global instance of the scan manager.
var Manager = &ScanManager{Status: "Idle"}

// --- UI-Driven (Asynchronous) Scan Functions ---

// StartNmapScanTask starts an nmap scan as a background task.
func (sm *ScanManager) StartNmapScanTask(target, campaignName string) (int64, error) {
	sm.mu.Lock()
	if sm.IsScanning {
		sm.mu.Unlock()
		return 0, fmt.Errorf("a scan is already in progress")
	}
	if !livecapture.IsNmapFound() {
		sm.mu.Unlock()
		return 0, fmt.Errorf("nmap executable not found")
	}

	sm.IsScanning = true
	sm.Status = fmt.Sprintf("Nmap scan starting on target %s...", target)
	ctx, cancel := context.WithCancel(context.Background())
	sm.cancelFunc = cancel
	sm.mu.Unlock()

	campaignID, err := storage.GetOrCreateCampaign(campaignName)
	if err != nil {
		sm.resetState()
		return 0, fmt.Errorf("could not create campaign: %w", err)
	}

	go func() {
		defer sm.resetState()
		log.Printf("Starting nmap scan for campaign '%s' on target '%s'", campaignName, target)
		err := livecapture.RunNmapScan(ctx, target, campaignName) // This now correctly expects only one return value (error)
		if err != nil {
			log.Printf("Error during nmap scan for campaign '%s': %v", campaignName, err)
			sm.mu.Lock()
			// Update status with error for user feedback
			sm.Status = fmt.Sprintf("Nmap scan failed: %v", err)
			sm.mu.Unlock()
			// Keep the error message for a bit before resetting to Idle
			<-time.After(10 * time.Second)
			return
		}
		log.Printf("✅ Nmap scan finished for campaign '%s'", campaignName)
	}()

	return campaignID, nil
}

func (sm *ScanManager) StartLiveScanTask(campaignName, interfaceName string) (int64, error) {
	sm.mu.Lock()
	if sm.IsScanning {
		sm.mu.Unlock()
		return 0, fmt.Errorf("a scan is already in progress")
	}

	sm.IsScanning = true
	sm.Status = fmt.Sprintf("Live capture starting on %s...", interfaceName)
	ctx, cancel := context.WithCancel(context.Background())
	sm.cancelFunc = cancel
	sm.mu.Unlock()

	campaignID, err := storage.GetOrCreateCampaign(campaignName)
	if err != nil {
		sm.resetState()
		return 0, fmt.Errorf("could not create campaign: %w", err)
	}

	go func() {
		defer sm.resetState()
		log.Printf("Starting background scan for campaign '%s'", campaignName)
		sm.mu.Lock()
		sm.Status = fmt.Sprintf("Live capture running on %s...", interfaceName)
		sm.mu.Unlock()

		masterMap := model.NewNetworkMap()
		globalSummary := model.NewPcapSummary()
		err := livecapture.Start(ctx, interfaceName, masterMap, globalSummary)
		if err != nil && err != context.Canceled {
			log.Printf("Error during live capture for campaign '%s': %v", campaignName, err)
			return
		}

		log.Printf("Live capture finished for '%s'. Finalizing...", campaignName)
		sm.mu.Lock()
		sm.Status = fmt.Sprintf("Finalizing data for '%s'...", campaignName)
		sm.mu.Unlock()

		processing.ProcessHandshakes(masterMap, globalSummary)
		processing.EnrichWithLookups(masterMap, globalSummary)

		if err := storage.SaveScanResults(campaignID, masterMap, globalSummary); err != nil {
			log.Printf("Error saving results for '%s': %v", campaignName, err)
		}
		log.Printf("✅ Scan results saved for campaign '%s'.", campaignName)
	}()

	return campaignID, nil
}

func (sm *ScanManager) StartFileScanTask(campaignName, dataDir string) (int64, error) {
	sm.mu.Lock()
	if sm.IsScanning {
		sm.mu.Unlock()
		return 0, fmt.Errorf("a scan is already in progress")
	}

	sm.IsScanning = true
	sm.Status = fmt.Sprintf("File scan starting in directory '%s'...", dataDir)
	sm.mu.Unlock()

	campaignID, err := storage.GetOrCreateCampaign(campaignName)
	if err != nil {
		sm.resetState()
		return 0, fmt.Errorf("could not create campaign: %w", err)
	}

	go func() {
		defer sm.resetState()
		log.Printf("Starting file scan for campaign '%s'", campaignName)
		if err := RunFileScan(campaignName, dataDir, campaignID); err != nil {
			log.Printf("Error during file scan task: %v", err)
		}
	}()

	return campaignID, nil
}

func (sm *ScanManager) StopScan() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.cancelFunc != nil {
		log.Println("Stopping active scan via API call.")
		sm.cancelFunc()
	}
}

func (sm *ScanManager) resetState() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.IsScanning = false
	sm.Status = "Idle"
	sm.cancelFunc = nil
}

func (sm *ScanManager) GetStatus() (bool, string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.IsScanning, sm.Status
}

// --- CLI-Driven (Synchronous) Scan Functions ---

func RunLiveScanBlocking(campaignName, interfaceName string) {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		fmt.Println("\n🛑 Stopping capture...")
		cancel()
	}()

	campaignID, err := storage.GetOrCreateCampaign(campaignName)
	if err != nil {
		log.Fatalf("Error handling campaign '%s': %v", campaignName, err)
	}
	fmt.Printf("✅ Operating on Campaign: '%s' (ID: %d)\n", campaignName, campaignID)

	masterMap := model.NewNetworkMap()
	globalSummary := model.NewPcapSummary()

	fmt.Printf("🚀 Starting live capture on interface '%s'. Press Ctrl+C to stop.\n", interfaceName)
	err = livecapture.Start(ctx, interfaceName, masterMap, globalSummary)
	if err != nil && err != context.Canceled {
		log.Fatalf("FATAL: Could not start live capture: %v", err)
	}
	fmt.Println("✅ Capture stopped.")

	fmt.Println("\n--- Finalizing data ---")
	processing.ProcessHandshakes(masterMap, globalSummary)
	processing.EnrichWithLookups(masterMap, globalSummary)

	if len(globalSummary.CapturedHandshakes) > 0 {
		fmt.Println("\n--- 🤝 Captured Handshakes ---")
		for i, hs := range globalSummary.CapturedHandshakes {
			fmt.Printf("  Handshake %d:\n", i+1)
			fmt.Printf("    - SSID:         %s\n", hs.SSID)
			fmt.Printf("    - AP MAC:       %s\n", hs.APMAC)
			fmt.Printf("    - Client MAC:   %s\n", hs.ClientMAC)
			fmt.Printf("    - State:        %s\n", hs.HandshakeState)
			fmt.Printf("    - Pcap Source:  %s\n", hs.PcapFile)
		}
	}

	fmt.Println("\n--- Saving results to database ---")
	if err := storage.SaveScanResults(campaignID, masterMap, globalSummary); err != nil {
		log.Fatalf("FATAL: Could not save results to database: %v", err)
	}
	fmt.Println("✅ Scan results saved successfully.")
}

func RunFileScanBlocking(campaignName, dataDir string) error {
	campaignID, err := storage.GetOrCreateCampaign(campaignName)
	if err != nil {
		return fmt.Errorf("error handling campaign '%s': %w", campaignName, err)
	}
	return RunFileScan(campaignName, dataDir, campaignID)
}

func RunFileScan(campaignName, dataDir string, campaignID int64) error {
	cleanDataDir := strings.TrimSpace(dataDir)
	cleanDataDir = strings.Trim(cleanDataDir, "\"")
	cleanDataDir = filepath.Clean(cleanDataDir)

	fmt.Printf("🔎 Searching for files in '%s'...\n", cleanDataDir)
	xmlFiles, pcapFiles, err := findDataFiles(cleanDataDir)
	if err != nil {
		return err
	}
	if len(xmlFiles) == 0 && len(pcapFiles) == 0 {
		fmt.Printf("No new data files found in '%s'.\n", cleanDataDir)
		return nil
	}

	fmt.Printf("Found %d Nmap and %d Pcap files. Processing...\n", len(xmlFiles), len(pcapFiles))
	masterMap, globalSummary := processing.ProcessFiles(xmlFiles, pcapFiles)

	fmt.Println("\n--- Finalizing data ---")
	processing.ProcessHandshakes(masterMap, globalSummary)
	processing.EnrichWithLookups(masterMap, globalSummary)

	nmapHosts := []*model.Host{}
	for _, host := range masterMap.Hosts {
		if host.DiscoveredBy == "Nmap" {
			nmapHosts = append(nmapHosts, host)
		}
	}

	if len(nmapHosts) > 0 {
		fmt.Println("\n--- 📡 Nmap Scan Results ---")
		sort.Slice(nmapHosts, func(i, j int) bool {
			return nmapHosts[i].MACAddress < nmapHosts[j].MACAddress
		})
		for _, host := range nmapHosts {
			fmt.Printf("Host: %s (%s)\n", host.MACAddress, host.Fingerprint.Vendor)
			fmt.Printf("  - Status: %s\n", host.Status)
			var ips []string
			for ip := range host.IPv4Addresses {
				ips = append(ips, ip)
			}
			if len(ips) > 0 {
				fmt.Printf("  - IP Addresses: %s\n", strings.Join(ips, ", "))
			}
			if host.Fingerprint.OperatingSystem != "" {
				fmt.Printf("  - OS Guess: %s\n", host.Fingerprint.OperatingSystem)
			}
			if len(host.Ports) > 0 {
				fmt.Println("  - Open Ports:")
				for _, port := range host.Ports {
					fmt.Printf("    - %d/%s (%s): %s\n", port.ID, port.Protocol, port.State, port.Version)
				}
			}
			fmt.Println("--------------------")
		}
	}

	if len(globalSummary.CapturedHandshakes) > 0 {
		fmt.Println("\n--- 🤝 Captured Handshakes ---")
		for i, hs := range globalSummary.CapturedHandshakes {
			fmt.Printf("  Handshake %d:\n", i+1)
			fmt.Printf("    - SSID:         %s\n", hs.SSID)
			fmt.Printf("    - AP MAC:       %s\n", hs.APMAC)
			fmt.Printf("    - Client MAC:   %s\n", hs.ClientMAC)
			fmt.Printf("    - State:        %s\n", hs.HandshakeState)
			fmt.Printf("    - Pcap Source:  %s\n", hs.PcapFile)
		}
	}

	fmt.Println("\n--- Saving results to database ---")
	if err := storage.SaveScanResults(campaignID, masterMap, globalSummary); err != nil {
		return fmt.Errorf("error saving results for '%s': %w", campaignName, err)
	}
	fmt.Println("✅ Scan results saved successfully.")
	return nil
}

func findDataFiles(rootDir string) ([]string, []string, error) {
	var xmlFiles, pcapFiles []string
	info, err := os.Stat(rootDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("directory does not exist: %s", rootDir)
		}
		return nil, nil, fmt.Errorf("could not access directory %s: %w", rootDir, err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("path is not a directory: %s", rootDir)
	}
	walkErr := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".xml" {
				xmlFiles = append(xmlFiles, path)
			} else if ext == ".pcap" || ext == ".pcapng" {
				pcapFiles = append(pcapFiles, path)
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, nil, fmt.Errorf("error walking directory %s: %w", rootDir, walkErr)
	}
	return xmlFiles, pcapFiles, nil
}
