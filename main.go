package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"gonetmap/config"
	"gonetmap/livecapture"
	"gonetmap/lookups"
	"gonetmap/scanner"
	"gonetmap/server"
	"gonetmap/storage"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/pkg/browser"
)

//go:embed templates/*
var templatesFS embed.FS

// checkForUpdates fetches the latest release from GitHub and compares versions.
func checkForUpdates(cfg *config.Config) {
	re := regexp.MustCompile(`github\.com/([^/]+)/([^/]+)`)
	matches := re.FindStringSubmatch(cfg.Application.GithubURL)
	if len(matches) < 3 {
		log.Println("Could not parse GitHub URL for update check.")
		return
	}
	owner, repo := matches[1], matches[2]

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)

	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Update check failed: %v", err)
		return
	}
	defer resp.Body.Close()

	// **FIX**: Handle 404 Not Found gracefully. This occurs when no releases exist.
	if resp.StatusCode == http.StatusNotFound {
		log.Println("✅ No public releases found on GitHub. Assuming application is up to date.")
		return // Not an error, just exit the check.
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Update check failed with status: %s", resp.Status)
		return
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		log.Printf("Could not decode GitHub API response: %v", err)
		return
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := cfg.Application.Version

	if latestVersion > currentVersion {
		log.Printf("📢 New version available: %s (current: %s)", release.TagName, currentVersion)
		cfg.Application.UpdateAvailable = true
		cfg.Application.LatestVersion = release.TagName
	} else {
		log.Println("✅ Application is up to date.")
	}
}

func main() {
	if err := config.LoadConfig(); err != nil {
		log.Fatalf("FATAL: Could not load configuration: %v", err)
	}

	go checkForUpdates(config.Cfg)

	if err := storage.InitDB(config.Cfg.Database.Path); err != nil {
		log.Fatalf("FATAL: Could not initialize database: %v", err)
	}
	if err := lookups.InitMac(); err != nil {
		log.Fatalf("FATAL: Could not initialize MAC lookup service: %v", err)
	}
	if err := lookups.InitGeoIP(config.Cfg); err != nil {
		log.Fatalf("FATAL: Could not initialize GeoIP service: %v", err)
	}
	if err := livecapture.InitNmap(config.Cfg); err != nil {
		log.Printf("WARNING: %v", err)
	}

	// --- Command-line flags ---
	campaignName := flag.String("campaign", "", "Name of the campaign for a new scan.")
	openCampaignName := flag.String("open", "", "Name of the campaign to open in the web UI.")
	openCampaignID := flag.Int("open-id", 0, "ID of the campaign to open in the web UI.")
	listCampaigns := flag.Bool("list", false, "List all existing campaigns in the terminal and exit.")
	dataDir := flag.String("dir", config.Cfg.DefaultPaths.DataDir, "Directory for file-based scans.")
	liveCapture := flag.Bool("live", false, "Enable live packet capture mode (requires -campaign and -iface).")
	iface := flag.String("iface", "", "Interface for live capture (use index number or full device name).")
	compareFlag := flag.String("compare", "", "Compare two campaigns by name or ID, separated by a comma. e.g., 'CampaignA,CampaignB' or '1,2'")
	nmapTarget := flag.String("nmap", "", "Run a live Nmap scan on the specified target (requires -campaign).")
	noUI := flag.Bool("no-ui", false, "Run in CLI-only mode without starting the web server.")

	flag.Parse()

	if strings.HasSuffix(*dataDir, " -no-ui") {
		*dataDir = strings.TrimSuffix(*dataDir, " -no-ui")
		*noUI = true
	}

	// --- Command-Line Dispatcher ---
	if *listCampaigns {
		handleListCampaignsCLI()
		return
	}

	if *compareFlag != "" {
		parts := strings.Split(*compareFlag, ",")
		if len(parts) != 2 {
			log.Fatal("FATAL: The -compare flag requires two campaign names or IDs, separated by a comma.")
		}
		handleCompareCLI(parts[0], parts[1], *noUI)
		return
	}

	if *liveCapture {
		devices, err := livecapture.ListInterfaces()
		if err != nil {
			log.Fatalf("FATAL: Could not list network interfaces: %v", err)
		}

		if *iface == "" {
			handleListInterfacesCLI(devices)
			return
		}
		if *campaignName == "" {
			log.Fatal("FATAL: A campaign name is required for a live scan (-campaign).")
		}

		var selectedDeviceName string
		if ifaceIndex, err := strconv.Atoi(*iface); err == nil {
			if ifaceIndex > 0 && ifaceIndex <= len(devices) {
				selectedDeviceName = devices[ifaceIndex-1].Name
				fmt.Printf("✅ Using interface [%d]: %s\n", ifaceIndex, devices[ifaceIndex-1].Description)
			} else {
				log.Fatalf("FATAL: Invalid interface index '%d'. Please choose a number between 1 and %d.", ifaceIndex, len(devices))
			}
		} else {
			selectedDeviceName = *iface
			found := false
			for _, d := range devices {
				if d.Name == selectedDeviceName {
					found = true
					break
				}
			}
			if !found {
				log.Fatalf("FATAL: Interface with name '%s' not found.", selectedDeviceName)
			}
		}

		scanner.RunLiveScanBlocking(*campaignName, selectedDeviceName)
		campaignID, _ := storage.GetOrCreateCampaign(*campaignName)
		launchServerAndBrowser(fmt.Sprintf("http://localhost:8080/campaign/%d", campaignID), templatesFS, *noUI)
		return
	}

	if *nmapTarget != "" {
		if *campaignName == "" {
			log.Fatal("FATAL: A campaign name is required for an Nmap scan (-campaign).")
		}
		scanner.RunNmapScanBlocking(*campaignName, *nmapTarget)
		campaignID, _ := storage.GetOrCreateCampaign(*campaignName)
		launchServerAndBrowser(fmt.Sprintf("http://localhost:8080/campaign/%d", campaignID), templatesFS, *noUI)
		return
	}

	if *campaignName != "" {
		if err := scanner.RunFileScanBlocking(*campaignName, *dataDir); err != nil {
			log.Fatalf("FATAL: File scan failed: %v", err)
		}
		campaignID, _ := storage.GetOrCreateCampaign(*campaignName)
		launchServerAndBrowser(fmt.Sprintf("http://localhost:8080/campaign/%d", campaignID), templatesFS, *noUI)
		return
	}

	if *openCampaignName != "" {
		campaignID, err := storage.GetOrCreateCampaign(*openCampaignName)
		if err != nil {
			log.Fatalf("FATAL: Could not find or create campaign '%s': %v", *openCampaignName, err)
		}
		launchServerAndBrowser(fmt.Sprintf("http://localhost:8080/campaign/%d", campaignID), templatesFS, *noUI)
		return
	}

	if *openCampaignID != 0 {
		_, err := storage.GetCampaignByID(int64(*openCampaignID))
		if err != nil {
			log.Fatalf("FATAL: No campaign found with ID %d: %v", *openCampaignID, err)
		}
		launchServerAndBrowser(fmt.Sprintf("http://localhost:8080/campaign/%d", *openCampaignID), templatesFS, *noUI)
		return
	}

	fmt.Println("✅ Starting server...")
	launchServerAndBrowser("http://localhost:8080/", templatesFS, *noUI)
}

func handleListCampaignsCLI() {
	campaigns, err := storage.ListCampaigns()
	if err != nil {
		log.Fatalf("Error listing campaigns: %v", err)
	}
	if len(campaigns) == 0 {
		fmt.Println("No campaigns found.")
		return
	}
	fmt.Println("--- Existing Campaigns ---")
	for _, c := range campaigns {
		fmt.Printf("  - ID: %d, Name: %s, Created: %s\n", c.ID, c.Name, c.CreatedAt.Format("2006-01-02 15:04:05"))
	}
}

func handleListInterfacesCLI(devices []pcap.Interface) {
	if len(devices) == 0 {
		fmt.Println("No network interfaces found. Make sure you have the necessary permissions.")
		return
	}
	fmt.Println("--- Available Network Interfaces ---")
	for i, device := range devices {
		fmt.Printf("\n[%d] %s\n", i+1, device.Description)
		var ipAddresses []string
		for _, address := range device.Addresses {
			ipAddresses = append(ipAddresses, address.IP.String())
		}
		if len(ipAddresses) > 0 {
			fmt.Printf("    IP Addresses: %s\n", strings.Join(ipAddresses, ", "))
		}
		fmt.Printf("    Device Name:  %s\n", device.Name)
	}
	fmt.Println("------------------------------------")
	fmt.Println("\nTo start a live capture, run the command again with the -iface flag, using the index number, e.g.:")
	fmt.Println("go run . -campaign \"Live Test\" -live -iface 5")
}

func handleCompareCLI(baseIdentifier, compareIdentifier string, noUI bool) {
	getCampaignID := func(identifier string) int64 {
		id, err := strconv.ParseInt(identifier, 10, 64)
		if err == nil {
			_, err := storage.GetCampaignByID(id)
			if err != nil {
				log.Fatalf("FATAL: No campaign found with ID %d: %v", id, err)
			}
			return id
		}
		id, err = storage.GetOrCreateCampaign(identifier)
		if err != nil {
			log.Fatalf("FATAL: Could not find or create campaign '%s': %v", identifier, err)
		}
		return id
	}

	baseID := getCampaignID(baseIdentifier)
	compareID := getCampaignID(compareIdentifier)

	if baseID == compareID {
		log.Fatal("FATAL: Cannot compare a campaign with itself. Please provide two different campaigns.")
	}

	fmt.Printf("Comparing Base Campaign '%s' (ID: %d) with Comparison Campaign '%s' (ID: %d)...\n", baseIdentifier, baseID, compareIdentifier, compareID)

	results, err := server.CompareCampaigns(baseID, compareID)
	if err != nil {
		log.Fatalf("FATAL: Failed to compare campaigns: %v", err)
	}

	fmt.Println("\n--- Comparison Results ---")

	fmt.Printf("\n[+] New Hosts (%d):\n", len(results.NewHosts))
	if len(results.NewHosts) > 0 {
		for _, host := range results.NewHosts {
			fmt.Printf("  - MAC: %s, Vendor: %s\n", host.MACAddress, host.Fingerprint.Vendor)
		}
	} else {
		fmt.Println("  None")
	}

	fmt.Printf("\n[-] Missing Hosts (%d):\n", len(results.MissingHosts))
	if len(results.MissingHosts) > 0 {
		for _, host := range results.MissingHosts {
			fmt.Printf("  - MAC: %s, Vendor: %s\n", host.MACAddress, host.Fingerprint.Vendor)
		}
	} else {
		fmt.Println("  None")
	}

	fmt.Printf("\n[*] Changed Hosts (%d):\n", len(results.ChangedHosts))
	if len(results.ChangedHosts) > 0 {
		for _, change := range results.ChangedHosts {
			fmt.Printf("  - MAC: %s\n", change.Host.MACAddress)
			for _, desc := range change.Changes {
				fmt.Printf("    - %s\n", desc)
			}
		}
	} else {
		fmt.Println("  None")
	}

	launchServerAndBrowser(fmt.Sprintf("http://localhost:8080/compare?base=%d&compare=%d", baseID, compareID), templatesFS, noUI)
}

func launchServerAndBrowser(url string, fs embed.FS, noUI bool) {
	if noUI {
		fmt.Println("\n--no-ui flag detected. Skipping server launch. Task complete.")
		return
	}

	go server.Start(fs)

	if url != "" {
		fmt.Println("\nLaunching browser to view results...")
		go func() {
			<-time.After(1 * time.Second)
			browser.OpenURL(url)
		}()
	}

	select {}
}
