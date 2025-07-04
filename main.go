package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"gonetmap/functions"
	"gonetmap/model"
	"gonetmap/storage"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/google/gopacket/layers"
	"github.com/pkg/browser"
)

//go:embed templates/*
var templatesFS embed.FS

func main() {
	// --- 1. Initialize backend services ---
	if err := storage.InitDB("gonetmap.db"); err != nil {
		log.Fatalf("FATAL: Could not initialize database: %v", err)
	}
	if err := functions.InitMac(); err != nil {
		log.Fatalf("FATAL: Could not initialize MAC lookup service: %v", err)
	}

	// --- 2. Define and parse all flags ---
	campaignName := flag.String("campaign", "", "Name of the campaign to scan and add data to.")
	openCampaignName := flag.String("open", "", "Name of the campaign to open in the web UI without running a new scan.")
	listCampaigns := flag.Bool("list", false, "List all existing campaigns.")
	dataDir := flag.String("dir", "./data", "Directory containing Nmap XML and Pcap files.")

	// Flags for live capture
	liveCapture := flag.Bool("live", false, "Enable live packet capture mode.")
	iface := flag.String("iface", "", "Interface to capture packets from (use -live to see options).")

	flag.Parse()

	// --- 3. Handle different modes ---

	// Live capture mode
	if *liveCapture {
		// FIX: If no interface is specified, the user just wants to see the list.
		// This check must come BEFORE the campaign name check.
		if *iface == "" {
			if err := functions.ListInterfaces(); err != nil {
				log.Fatalf("FATAL: Could not list network interfaces: %v", err)
			}
			return // Exit after listing interfaces
		}

		// If an interface IS specified, we now need a campaign name.
		if *campaignName == "" {
			log.Fatalf("FATAL: A campaign name is required when specifying an interface. Use the -campaign flag.")
		}

		// If we have both an interface and a campaign, start the capture.
		handleLiveCapture(*campaignName, *iface)
		return
	}

	if *listCampaigns {
		handleListCampaigns()
		return
	}

	if *campaignName != "" {
		handleScanCampaign(*campaignName, *dataDir)
		return
	}

	if *openCampaignName != "" {
		campaignID, err := storage.GetOrCreateCampaign(*openCampaignName)
		if err != nil {
			log.Fatalf("Error finding campaign '%s': %v", *openCampaignName, err)
		}
		fmt.Printf("✅ Opening Campaign: '%s' (ID: %d)\n", *openCampaignName, campaignID)
		launchServerAndBrowser(fmt.Sprintf("http://localhost:8080/campaign/%d", campaignID), templatesFS)
		return
	}

	fmt.Println("✅ No specific campaign requested. Starting server...")
	launchServerAndBrowser("http://localhost:8080/", templatesFS)
}

// handleLiveCapture orchestrates the real-time packet capture process.
func handleLiveCapture(campaignName, interfaceName string) {
	campaignID, err := storage.GetOrCreateCampaign(campaignName)
	if err != nil {
		log.Fatalf("Error handling campaign '%s': %v", campaignName, err)
	}
	fmt.Printf("✅ Operating on Campaign: '%s' (ID: %d)\n", campaignName, campaignID)

	masterMap := model.NewNetworkMap()
	globalSummary := model.NewPcapSummary()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Printf("🚀 Starting live capture on interface '%s'. Press Ctrl+C to stop.\n", interfaceName)
		if err := functions.StartLiveCapture(ctx, interfaceName, masterMap, globalSummary); err != nil {
			log.Fatalf("FATAL: Could not start live capture: %v", err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	fmt.Println("\n🛑 Stopping capture...")
	cancel()
	wg.Wait()
	fmt.Println("✅ Capture stopped.")

	fmt.Println("\n--- Finalizing data ---")
	ProcessHandshakes(masterMap, globalSummary)
	enrichWithLookups(masterMap, globalSummary)

	fmt.Println("\n--- Saving results to database ---")
	if err := storage.SaveScanResults(campaignID, masterMap, globalSummary); err != nil {
		log.Fatalf("FATAL: Could not save results to database: %v", err)
	}
	fmt.Println("✅ Scan results saved successfully.")

	fmt.Println("\n--- Generating Console Report ---")
	printConsoleReport(masterMap, globalSummary)
	fmt.Println("\n✅ Console report generated.")

	fmt.Println("\n✅ Scan complete. Starting server and opening browser...")
	launchServerAndBrowser(fmt.Sprintf("http://localhost:8080/campaign/%d", campaignID), templatesFS)
}

// processFiles handles the core logic of parsing and enrichment concurrently.
func processFiles(xmlFiles, pcapFiles []string) (*model.NetworkMap, *model.PcapSummary) {
	masterMap := model.NewNetworkMap()
	var mapMutex sync.Mutex

	var wg sync.WaitGroup
	errChan := make(chan error, len(xmlFiles)+len(pcapFiles))

	var processedCount int32
	totalFiles := int32(len(xmlFiles) + len(pcapFiles))
	done := make(chan bool)

	go func() {
		for {
			select {
			case <-done:
				return
			default:
				fmt.Printf("\rProcessing files: %d/%d", atomic.LoadInt32(&processedCount), totalFiles)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	if len(xmlFiles) > 0 {
		fmt.Println("\n--- Parsing Nmap files ---")
		for _, file := range xmlFiles {
			wg.Add(1)
			go func(filePath string) {
				defer wg.Done()
				defer atomic.AddInt32(&processedCount, 1)

				tempMap := model.NewNetworkMap()
				if err := functions.MergeFromFile(filePath, tempMap); err != nil {
					errChan <- fmt.Errorf("could not parse Nmap file %s: %w", filePath, err)
					return
				}

				mapMutex.Lock()
				for k, v := range tempMap.Hosts {
					masterMap.Hosts[k] = v
				}
				mapMutex.Unlock()
			}(file)
		}
		wg.Wait()
	}

	globalSummary := model.NewPcapSummary()
	var pcapMutex sync.Mutex

	if len(pcapFiles) > 0 {
		fmt.Println("\n--- Enriching with Pcap files ---")
		for _, file := range pcapFiles {
			wg.Add(1)
			go func(filePath string) {
				defer wg.Done()
				defer atomic.AddInt32(&processedCount, 1)

				pcapMutex.Lock()
				defer pcapMutex.Unlock()

				if err := functions.EnrichData(filePath, masterMap, globalSummary); err != nil {
					errChan <- fmt.Errorf("could not process pcap file %s: %w", filePath, err)
					return
				}
			}(file)
		}
		wg.Wait()
	}

	done <- true
	fmt.Printf("\rProcessing files: %d/%d... Done.\n", atomic.LoadInt32(&processedCount), totalFiles)

	close(errChan)
	hasErrors := false
	for err := range errChan {
		if !hasErrors {
			fmt.Println("\n--- Warnings ---")
			hasErrors = true
		}
		log.Printf("  - %v", err)
	}
	if hasErrors {
		fmt.Println("NOTE: Some files could not be processed completely. See warnings above.")
	}

	fmt.Printf("\n✅ File processing complete. Found %d unique hosts.\n\n", len(masterMap.Hosts))

	ProcessHandshakes(masterMap, globalSummary)
	enrichWithLookups(masterMap, globalSummary)

	return masterMap, globalSummary
}

// enrichWithLookups performs GeoIP and MAC vendor lookups.
func enrichWithLookups(networkMap *model.NetworkMap, summary *model.PcapSummary) {
	fmt.Println("--- Performing Geolocation Lookups ---")
	geoCache := make(map[string]*model.GeoInfo)
	for _, host := range networkMap.Hosts {
		for _, comm := range host.Communications {
			if geoInfo, found := geoCache[comm.CounterpartIP]; found {
				comm.Geo = geoInfo
				continue
			}
			geoInfo, err := functions.LookupIP(comm.CounterpartIP)
			if err != nil {
				log.Printf("Could not get geo info for %s: %v", comm.CounterpartIP, err)
			}
			if geoInfo != nil {
				fmt.Printf("  -> Found %s -> %s, %s (%s)\n", comm.CounterpartIP, geoInfo.City, geoInfo.Country, geoInfo.ISP)
				comm.Geo = geoInfo
				geoCache[comm.CounterpartIP] = geoInfo
			}
		}
	}
	fmt.Println("✅ Geolocation enrichment complete.")

	fmt.Println("\n--- Performing Local MAC Vendor Lookups ---")
	allMacsToLookup := make(map[string]string)
	for mac := range summary.UnidentifiedMACs {
		allMacsToLookup[mac] = ""
	}
	for _, host := range networkMap.Hosts {
		if (host.Fingerprint == nil || host.Fingerprint.Vendor == "") && host.MACAddress != "" {
			allMacsToLookup[host.MACAddress] = ""
		}
	}

	if len(allMacsToLookup) > 0 {
		fmt.Printf("  -> Found %d unique MACs to look up.\n", len(allMacsToLookup))
		for mac := range allMacsToLookup {
			vendor, err := functions.LookupVendor(mac)
			if err == nil && vendor != "Unknown Vendor" {
				allMacsToLookup[mac] = vendor
			}
		}
		for mac, vendor := range allMacsToLookup {
			if vendor == "" {
				continue
			}
			if host, ok := networkMap.Hosts[mac]; ok {
				if host.Fingerprint == nil {
					host.Fingerprint = &model.Fingerprint{}
				}
				host.Fingerprint.Vendor = vendor
			}
			if _, ok := summary.UnidentifiedMACs[mac]; ok {
				summary.UnidentifiedMACs[mac] = vendor
			}
		}
		fmt.Println("✅ Local MAC Vendor lookup complete.")
	} else {
		fmt.Println("No new MAC addresses to look up.")
	}
}

// printConsoleReport contains all the logic for printing the final report.
func printConsoleReport(networkMap *model.NetworkMap, summary *model.PcapSummary) {
	fmt.Println("\n\n===================================================")
	fmt.Println("          Host-Centric Network Report")
	fmt.Println("===================================================")

	var sortedHosts []*model.Host
	for _, host := range networkMap.Hosts {
		sortedHosts = append(sortedHosts, host)
	}
	sort.Slice(sortedHosts, func(i, j int) bool { return sortedHosts[i].MACAddress < sortedHosts[j].MACAddress })

	for _, host := range sortedHosts {
		var ips []string
		for ip := range host.IPv4Addresses {
			ips = append(ips, ip)
		}
		fmt.Printf("\n--- Host MAC: %s ---\n", host.MACAddress)
		if len(ips) > 0 {
			fmt.Printf("  IP Addresses: %s\n", strings.Join(ips, ", "))
		}
		if host.Status != "" {
			fmt.Printf("  Status: %s\n", host.Status)
		} else {
			fmt.Printf("  Status: Unknown (from pcap)\n")
		}

		if host.Fingerprint != nil {
			fmt.Printf("  Device Fingerprint:\n")
			if host.Fingerprint.Vendor != "" {
				fmt.Printf("    Vendor: %s\n", host.Fingerprint.Vendor)
			}
			if host.Fingerprint.OperatingSystem != "" {
				fmt.Printf("    Nmap OS Guess: %s\n", host.Fingerprint.OperatingSystem)
			}
			if host.Fingerprint.DeviceType != "" {
				fmt.Printf("    Device Type: %s\n", host.Fingerprint.DeviceType)
			}
			if len(host.Fingerprint.BehavioralClues) > 0 {
				fmt.Printf("    Behavioral Clues:\n")
				for clue := range host.Fingerprint.BehavioralClues {
					fmt.Printf("      - %s\n", clue)
				}
			}
		}

		if host.Wifi != nil {
			fmt.Printf("  Wi-Fi Details:\n")
			if host.Wifi.DeviceRole != "" {
				fmt.Printf("    Role: %s\n", host.Wifi.DeviceRole)
			}
			if host.Wifi.SSID != "" {
				fmt.Printf("    SSID: %s\n", host.Wifi.SSID)
			}
			if host.Wifi.AssociatedAP != "" {
				fmt.Printf("    Connected to AP: %s\n", host.Wifi.AssociatedAP)
			}
			if len(host.Wifi.ProbeRequests) > 0 {
				var probes []string
				for ssid := range host.Wifi.ProbeRequests {
					probes = append(probes, ssid)
				}
				fmt.Printf("    Searching for SSIDs: %s\n", strings.Join(probes, ", "))
			}
			if host.Wifi.HandshakeState != "" {
				fmt.Printf("    WPA Handshake Captured: %s\n", host.Wifi.HandshakeState)
			}
		}

		if len(host.Ports) > 0 {
			fmt.Printf("  Nmap Ports:\n")
			for _, port := range host.Ports {
				versionInfo := port.Service
				if port.Version != " " && port.Version != "" {
					versionInfo += " " + port.Version
				}
				fmt.Printf("    - Port %d/%s (%s): %s\n", port.ID, port.Protocol, port.State, versionInfo)
			}
		}

		if len(host.Findings) > 0 {
			fmt.Printf("  Vulnerability & Information Summary:\n")
			displayOrder := []model.FindingCategory{model.CriticalFinding, model.PotentialFinding, model.InformationalFinding}
			for _, category := range displayOrder {
				if findings, ok := host.Findings[category]; ok {
					fmt.Printf("    --- %s ---\n", category)
					for _, vuln := range findings {
						title := ""
						if vuln.State != "" && vuln.State != "NOT VULNERABLE" {
							title = fmt.Sprintf("[%s] ", vuln.State)
						}
						title += vuln.CVE
						if vuln.PortID != 0 {
							fmt.Printf("      - Port %d: %s\n", vuln.PortID, title)
						} else {
							fmt.Printf("      - Host-Level: %s\n", title)
						}
						isVulners := vuln.CVE == "vulners"
						if isVulners {
							descriptionLines := strings.Split(vuln.Description, "\n")
							for i, line := range descriptionLines {
								trimmedLine := strings.TrimSpace(line)
								if trimmedLine == "" {
									continue
								}
								if i == 0 {
									fmt.Printf("        > %s\n", trimmedLine)
								} else {
									fmt.Printf("            %s\n", trimmedLine)
								}
							}
						} else if !strings.EqualFold(vuln.Description, vuln.CVE) {
							descriptionLines := strings.Split(vuln.Description, "\n")
							for _, line := range descriptionLines {
								if !strings.EqualFold(strings.TrimSpace(line), vuln.State) {
									fmt.Printf("          %s\n", strings.TrimSpace(line))
								}
							}
						}
					}
				}
			}
		}

		if len(host.Communications) > 0 {
			fmt.Printf("  Pcap Communications:\n")
			for counterpartIP, comm := range host.Communications {
				if comm.Geo != nil {
					fmt.Printf("    - Talked to %s (%d packets) -> [Location: %s, %s | ISP: %s]\n", counterpartIP, comm.PacketCount, comm.Geo.City, comm.Geo.Country, comm.Geo.ISP)
				} else {
					fmt.Printf("    - Talked to %s (%d packets)\n", counterpartIP, comm.PacketCount)
				}
			}
		}

		if len(host.DNSLookups) > 0 {
			fmt.Printf("  Observed DNS Lookups:\n")
			var domains []string
			for domain := range host.DNSLookups {
				domains = append(domains, domain)
			}
			sort.Strings(domains)
			for _, domain := range domains {
				fmt.Printf("    - %s\n", domain)
			}
		}
	}

	fmt.Println("\n\n===================================================")
	fmt.Println("            Global Pcap Summary")
	fmt.Println("===================================================")

	if len(summary.UnidentifiedMACs) > 0 {
		fmt.Printf("\n--- Unidentified Devices (Seen in Pcap but not Nmap) ---\n")
		for mac, vendor := range summary.UnidentifiedMACs {
			if vendor != "" && vendor != "Unknown Vendor" {
				parts := strings.Split(mac, ":")
				if len(parts) == 6 {
					lastHalf := strings.Join(parts[3:], ":")
					cleanVendor := strings.Split(vendor, ",")[0]
					fmt.Printf("  - %s-%s\n", cleanVendor, lastHalf)
				} else {
					fmt.Printf("  - %s (%s)\n", mac, vendor)
				}
			} else {
				fmt.Printf("  - %s\n", mac)
			}
		}
	}

	if len(summary.AdvertisedAPs) > 0 {
		fmt.Printf("\n--- Advertising Access Points (Seen via Beacons) ---\n")
		for ssid, apMACs := range summary.AdvertisedAPs {
			var macList []string
			for mac := range apMACs {
				macList = append(macList, mac)
			}
			displaySSID := cleanString(ssid)
			if displaySSID == "" {
				displaySSID = "<Hidden SSID>"
			}
			fmt.Printf("  - SSID: %-25s | AP MAC(s): %s\n", displaySSID, strings.Join(macList, ", "))
		}
	}

	if len(summary.AllProbeRequests) > 0 {
		fmt.Printf("\n--- Wi-Fi Probe Requests (Client Devices Searching) ---\n")
		for ssid, probers := range summary.AllProbeRequests {
			count := len(probers)
			displaySSID := cleanString(ssid)
			if displaySSID == "" {
				displaySSID = "<Hidden SSID>"
			}
			fmt.Printf("  - SSID: %-25s | (Probed by %d unique device(s))\n", displaySSID, count)
		}
	}

	if len(summary.ProtocolCounts) > 0 {
		fmt.Printf("\n--- Overall Protocol Statistics ---\n")
		for proto, count := range summary.ProtocolCounts {
			fmt.Printf("  - %-25s : %d packets\n", proto, count)
		}
	}

	if len(summary.CapturedHandshakes) > 0 {
		fmt.Println("\n\n===================================================")
		fmt.Println("     Captured Handshakes (for Cracking)")
		fmt.Println("===================================================")
		fmt.Println("\nInstructions: To use these handshakes with a tool like hashcat,")
		fmt.Println("copy the 'HCCAPX_HEX' data into a text file, then convert it back")
		fmt.Println("to a binary file. For example, in Linux/macOS, you can use:")
		fmt.Println("  xxd -r -p <your_hex_file> > handshake.hccapx")

		for _, hs := range summary.CapturedHandshakes {
			fmt.Printf("\n--- Handshake for SSID: %s ---\n", hs.SSID)
			fmt.Printf("  Access Point MAC: %s\n", hs.APMAC)
			fmt.Printf("  Client MAC:       %s\n", hs.ClientMAC)
			fmt.Printf("  Pcap File:        %s\n", hs.PcapFile)
			fmt.Printf("  HCCAPX_HEX:       %s\n", hs.ToHCCAPXString())
		}
	}
}

// handleListCampaigns lists all campaigns and exits.
func handleListCampaigns() {
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

// handleScanCampaign performs the full scan and then calls the blocking server/browser launcher.
func handleScanCampaign(name, dataDir string) {
	dataDir = strings.Trim(dataDir, "\"")
	cleanDataDir := filepath.Clean(dataDir)

	campaignID, err := storage.GetOrCreateCampaign(name)
	if err != nil {
		log.Fatalf("Error handling campaign '%s': %v", name, err)
	}
	fmt.Printf("✅ Operating on Campaign: '%s' (ID: %d)\n", name, campaignID)

	xmlFiles, pcapFiles, err := findDataFiles(cleanDataDir)
	if err != nil {
		log.Fatalf("FATAL: Could not find data files: %v", err)
	}
	if len(xmlFiles) == 0 && len(pcapFiles) == 0 {
		fmt.Printf("No new data files found in '%s' directory. Launching UI with existing data.\n", cleanDataDir)
	} else {
		fmt.Printf("🔎 Found %d Nmap files and %d Pcap files in '%s'.\n", len(xmlFiles), len(pcapFiles), cleanDataDir)
		masterMap, globalSummary := processFiles(xmlFiles, pcapFiles)
		fmt.Println("\n--- Saving results to database ---")
		if err := storage.SaveScanResults(campaignID, masterMap, globalSummary); err != nil {
			log.Fatalf("FATAL: Could not save results to database: %v", err)
		}
		fmt.Println("✅ Scan results saved successfully.")
		fmt.Println("\n--- Generating Console Report ---")
		printConsoleReport(masterMap, globalSummary)
		fmt.Println("\n✅ Console report generated.")
	}

	fmt.Println("\n✅ Scan complete. Starting server and opening browser...")
	launchServerAndBrowser(fmt.Sprintf("http://localhost:8080/campaign/%d", campaignID), templatesFS)
}

// launchServerAndBrowser starts the server in a goroutine and opens a URL.
func launchServerAndBrowser(url string, fs embed.FS) {
	go functions.StartServer(fs)
	if url != "" {
		browser.OpenURL(url)
	}
	select {}
}

// findDataFiles scans a directory for relevant data files.
func findDataFiles(rootDir string) (xmlFiles, pcapFiles []string, err error) {
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

// ProcessHandshakes refactored to take the summary object directly.
func ProcessHandshakes(networkMap *model.NetworkMap, summary *model.PcapSummary) {
	for sessionKey, packets := range summary.EapolTracker {
		macs := strings.Split(sessionKey, "-")
		if len(macs) != 2 {
			continue
		}

		msg1, msg2, msg3, msg4 := false, false, false, false
		var apMAC, clientMAC string

		for _, pkt := range packets {
			dot11, _ := pkt.Layer(layers.LayerTypeDot11).(*layers.Dot11)
			if dot11.Flags.ToDS() && !dot11.Flags.FromDS() {
				clientMAC = dot11.Address2.String()
				apMAC = dot11.Address1.String()
			} else if !dot11.Flags.ToDS() && dot11.Flags.FromDS() {
				apMAC = dot11.Address2.String()
				clientMAC = dot11.Address1.String()
			}
			if eapolLayer := pkt.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
				if dot11.Flags.ToDS() {
					msg2, msg4 = true, true
				}
				if dot11.Flags.FromDS() {
					msg1, msg3 = true, true
				}
			}
		}

		state := "Partial"
		if msg1 && msg2 && msg3 && msg4 {
			state = "Full"
		}

		for _, addr := range []string{strings.ToUpper(apMAC), strings.ToUpper(clientMAC)} {
			if addr == "" {
				continue
			}
			host, found := networkMap.Hosts[addr]
			if !found {
				host = model.NewHost(addr)
				host.DiscoveredBy = "Pcap (Handshake)"
				networkMap.Hosts[addr] = host
			}
			if host.Wifi == nil {
				host.Wifi = &model.WifiInfo{ProbeRequests: make(map[string]bool)}
			}
			host.Wifi.HandshakeState = state
			if addr == strings.ToUpper(apMAC) {
				host.Wifi.DeviceRole = "Access Point"
			} else {
				host.Wifi.DeviceRole = "Client"
			}
		}

		if state == "Full" {
			ssid := "UnknownSSID"
			if ap, ok := networkMap.Hosts[strings.ToUpper(apMAC)]; ok && ap.Wifi != nil && ap.Wifi.SSID != "" {
				ssid = ap.Wifi.SSID
			}

			var realHandshakeData []byte
			for _, pkt := range packets {
				if eapolLayer := pkt.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
					realHandshakeData = append(realHandshakeData, pkt.Data()...)
				}
			}

			lastPacket := packets[len(packets)-1]
			pcapFile := summary.PacketSources[lastPacket]

			summary.CapturedHandshakes = append(summary.CapturedHandshakes, model.Handshake{
				ClientMAC:      strings.ToUpper(clientMAC),
				APMAC:          strings.ToUpper(apMAC),
				SSID:           ssid,
				PcapFile:       pcapFile,
				HCCAPX:         realHandshakeData,
				HandshakeState: state,
			})
		}
	}
}

// cleanString is a helper for display.
func cleanString(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
}
