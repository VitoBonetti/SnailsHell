package main

import (
	"embed"
	"flag"
	"fmt"
	"gonetmap/config"
	"gonetmap/livecapture"
	"gonetmap/lookups"
	"gonetmap/scanner"
	"gonetmap/server"
	"gonetmap/storage"
	"log"
	"strings"
	"time"

	"github.com/pkg/browser"
)

//go:embed templates/*
var templatesFS embed.FS

func main() {
	if err := config.LoadConfig(); err != nil {
		log.Fatalf("FATAL: Could not load configuration: %v", err)
	}

	if err := storage.InitDB(config.Cfg.Database.Path); err != nil {
		log.Fatalf("FATAL: Could not initialize database: %v", err)
	}
	if err := lookups.InitMac(); err != nil {
		log.Fatalf("FATAL: Could not initialize MAC lookup service: %v", err)
	}

	// --- Command-line flags ---
	campaignName := flag.String("campaign", "", "Name of the campaign for a new scan.")
	openCampaignName := flag.String("open", "", "Name of the campaign to open in the web UI.")
	// NEW: Flag to open by ID
	openCampaignID := flag.Int("open-id", 0, "ID of the campaign to open in the web UI.")
	listCampaigns := flag.Bool("list", false, "List all existing campaigns in the terminal and exit.")
	dataDir := flag.String("dir", config.Cfg.DefaultPaths.DataDir, "Directory for file-based scans.")
	liveCapture := flag.Bool("live", false, "Enable live packet capture mode (requires -campaign and -iface).")
	iface := flag.String("iface", "", "Interface for live capture (use -live without this flag to see options).")

	flag.Parse()

	// --- Command-Line Dispatcher ---
	if *listCampaigns {
		handleListCampaignsCLI()
		return
	}

	if *liveCapture {
		if *iface == "" {
			handleListInterfacesCLI()
			return
		}
		if *campaignName == "" {
			log.Fatal("FATAL: A campaign name is required for a live scan (-campaign).")
		}
		scanner.RunLiveScanBlocking(*campaignName, *iface)
		campaignID, _ := storage.GetOrCreateCampaign(*campaignName)
		launchServerAndBrowser(fmt.Sprintf("http://localhost:8080/campaign/%d", campaignID), templatesFS)
		return
	}

	if *campaignName != "" {
		scanner.RunFileScanBlocking(*campaignName, *dataDir)
		campaignID, _ := storage.GetOrCreateCampaign(*campaignName)
		launchServerAndBrowser(fmt.Sprintf("http://localhost:8080/campaign/%d", campaignID), templatesFS)
		return
	}

	if *openCampaignName != "" {
		campaignID, err := storage.GetOrCreateCampaign(*openCampaignName)
		if err != nil {
			log.Fatalf("FATAL: Could not find or create campaign '%s': %v", *openCampaignName, err)
		}
		launchServerAndBrowser(fmt.Sprintf("http://localhost:8080/campaign/%d", campaignID), templatesFS)
		return
	}

	// NEW: Handle opening by ID
	if *openCampaignID != 0 {
		// Check if campaign exists to provide a better error message.
		_, err := storage.GetCampaignByID(int64(*openCampaignID))
		if err != nil {
			log.Fatalf("FATAL: No campaign found with ID %d: %v", *openCampaignID, err)
		}
		launchServerAndBrowser(fmt.Sprintf("http://localhost:8080/campaign/%d", *openCampaignID), templatesFS)
		return
	}

	// Default action: Start the server if no other flags are provided.
	fmt.Println("✅ Starting server...")
	launchServerAndBrowser("http://localhost:8080/", templatesFS)
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

func handleListInterfacesCLI() {
	devices, err := livecapture.ListInterfaces()
	if err != nil {
		log.Fatalf("FATAL: Could not list network interfaces: %v", err)
	}
	if len(devices) == 0 {
		fmt.Println("No network interfaces found. Make sure you have the necessary permissions.")
		return
	}
	fmt.Println("--- Available Network Interfaces ---")
	for _, device := range devices {
		fmt.Printf("Name: %s\n", device.Name)
		if device.Description != "" {
			fmt.Printf("  Description: %s\n", device.Description)
		}
		var ipAddresses []string
		for _, address := range device.Addresses {
			ipAddresses = append(ipAddresses, address.IP.String())
		}
		if len(ipAddresses) > 0 {
			fmt.Printf("  IP Addresses: %s\n", strings.Join(ipAddresses, ", "))
		}
		fmt.Println("------------------------------------")
	}
	fmt.Println("\nTo start a live capture, run the command again with the -iface flag, e.g.:")
	fmt.Printf("go run . -campaign \"Live Test\" -live -iface \"%s\"\n", devices[0].Name)
}

func launchServerAndBrowser(url string, fs embed.FS) {
	go server.Start(fs)
	if url != "" {
		go func() {
			<-time.After(1 * time.Second)
			browser.OpenURL(url)
		}()
	}
	select {}
}
