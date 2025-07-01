package main

import (
	"flag"
	"fmt"
	"gonetmap/functions"
	"gonetmap/model"
	"gonetmap/storage"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// --- The main function is now streamlined ---
func main() {
	// --- 1. Initialize backend services ---
	if err := storage.InitDB("gonetmap.db"); err != nil {
		log.Fatalf("FATAL: Could not initialize database: %v", err)
	}
	if err := functions.InitMac(); err != nil {
		log.Fatalf("FATAL: Could not initialize MAC lookup service: %v", err)
	}

	// --- 2. Parse the required --campaign flag ---
	campaignName := flag.String("campaign", "", "Name of the campaign to process (creates it if it doesn't exist)")
	flag.Parse()

	// --- 3. Validate Input ---
	if *campaignName == "" {
		fmt.Println("Error: The --campaign flag is required.")
		fmt.Println("Usage: go run . --campaign <campaign_name>")
		return
	}

	// --- 4. Get or Create the Campaign ---
	campaignID, err := storage.GetOrCreateCampaign(*campaignName)
	if err != nil {
		log.Fatalf("Error handling campaign: %v", err)
	}
	fmt.Printf("✅ Operating on Campaign: '%s' (ID: %d)\n", *campaignName, campaignID)

	// --- 5. Discover Data Files ---
	xmlFiles, pcapFiles, err := findDataFiles("./data")
	if err != nil {
		log.Fatalf("Error finding data files in ./data directory: %v", err)
	}
	if len(xmlFiles) == 0 && len(pcapFiles) == 0 {
		log.Println("No .xml or .pcap/.pcapng files found in ./data directory. Nothing to process.")
		return
	}
	fmt.Printf("🔎 Found %d Nmap files and %d Pcap files.\n", len(xmlFiles), len(pcapFiles))

	// --- 6. Parse, Process, and Enrich All Data ---
	masterMap, globalSummary := processFiles(xmlFiles, pcapFiles)

	// --- 7. Save Results to Database ---
	fmt.Println("\n--- Saving results to database ---")
	if err := storage.SaveScanResults(campaignID, masterMap, globalSummary); err != nil {
		log.Fatalf("FATAL: Could not save results to database: %v", err)
	}
	fmt.Println("✅ Scan results saved successfully.")

	// --- 8. Print Console Report ---
	fmt.Println("\n--- Generating Console Report ---")
	printConsoleReport(masterMap, globalSummary)
	fmt.Println("\n✅ Console report generated.")
}

// processFiles handles the core logic of parsing and enrichment.
func processFiles(xmlFiles, pcapFiles []string) (*model.NetworkMap, *model.PcapSummary) {
	masterMap := model.NewNetworkMap()
	fmt.Println("\n--- Parsing Nmap files ---")
	for _, file := range xmlFiles {
		if err := functions.MergeFromFile(file, masterMap); err != nil {
			log.Printf("Warning: could not parse Nmap file %s: %v", file, err)
		}
	}
	fmt.Printf("\n✅ Nmap parsing complete. Found %d unique hosts.\n\n", len(masterMap.Hosts))

	globalSummary := model.NewPcapSummary()
	eapolTracker := make(map[string][]gopacket.Packet)
	packetSources := make(map[gopacket.Packet]string)

	if len(pcapFiles) > 0 {
		fmt.Println("--- Enriching with Pcap files ---")
		for _, file := range pcapFiles {
			if err := functions.EnrichData(file, masterMap, globalSummary, eapolTracker, packetSources); err != nil {
				log.Printf("Warning: could not process pcap file %s: %v", file, err)
			}
		}
		fmt.Println("\n✅ Pcap enrichment complete.")
	}

	ProcessHandshakes(eapolTracker, masterMap, globalSummary, packetSources)

	fmt.Println("\n--- Performing Geolocation Lookups ---")
	geoCache := make(map[string]*model.GeoInfo)
	for _, host := range masterMap.Hosts {
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
	fmt.Println("\n✅ Geolocation enrichment complete.")

	fmt.Println("\n--- Performing Local MAC Vendor Lookups ---")
	allMacsToLookup := make(map[string]string)
	for mac := range globalSummary.UnidentifiedMACs {
		allMacsToLookup[mac] = ""
	}
	for _, host := range masterMap.Hosts {
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
			if host, ok := masterMap.Hosts[mac]; ok {
				if host.Fingerprint == nil {
					host.Fingerprint = &model.Fingerprint{}
				}
				host.Fingerprint.Vendor = vendor
			}
			if _, ok := globalSummary.UnidentifiedMACs[mac]; ok {
				globalSummary.UnidentifiedMACs[mac] = vendor
			}
		}
		fmt.Println("✅ Local MAC Vendor lookup complete.")
	} else {
		fmt.Println("No new MAC addresses to look up.")
	}

	return masterMap, globalSummary
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

// (findDataFiles, ProcessHandshakes, and cleanString functions remain the same)
func findDataFiles(rootDir string) (xmlFiles, pcapFiles []string, err error) {
	err = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".xml" {
				xmlFiles = append(xmlFiles, path)
			}
			if ext == ".pcap" || ext == ".pcapng" {
				pcapFiles = append(pcapFiles, path)
			}
		}
		return nil
	})
	return
}

func ProcessHandshakes(eapolTracker map[string][]gopacket.Packet, networkMap *model.NetworkMap, summary *model.PcapSummary, packetSources map[gopacket.Packet]string) {
	for sessionKey, packets := range eapolTracker {
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
				host = &model.Host{
					MACAddress:     addr,
					DiscoveredBy:   "Pcap (Handshake)",
					IPv4Addresses:  make(map[string]bool),
					Ports:          make(map[int]model.Port),
					Communications: make(map[string]*model.Communication),
					Findings:       make(map[model.FindingCategory][]model.Vulnerability),
					DNSLookups:     make(map[string]bool),
					Fingerprint:    &model.Fingerprint{BehavioralClues: make(map[string]bool)},
				}
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

			// Concatenate the raw data of all EAPOL packets for this session.
			// This is the real handshake data.
			var realHandshakeData []byte
			for _, pkt := range packets {
				if eapolLayer := pkt.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
					realHandshakeData = append(realHandshakeData, pkt.Data()...)
				}
			}

			lastPacket := packets[len(packets)-1]
			pcapFile := packetSources[lastPacket]

			summary.CapturedHandshakes = append(summary.CapturedHandshakes, model.Handshake{
				ClientMAC:      strings.ToUpper(clientMAC),
				APMAC:          strings.ToUpper(apMAC),
				SSID:           ssid,
				PcapFile:       pcapFile,
				HCCAPX:         realHandshakeData, // <-- Now using the real data
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
