package main

import (
	"fmt"
	"gonetmap/geoip"
	"gonetmap/maclookup"
	"gonetmap/model"
	"gonetmap/nmap"
	"gonetmap/pcap"
	"log"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Helper function to ensure an SSID is clean before printing
func cleanString(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
}

func main() {
	// (All parsing logic is unchanged)
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <file1.xml> ... <file1.pcapng> ...")
		return
	}
	var xmlFiles, pcapFiles []string
	for _, arg := range os.Args[1:] {
		if strings.HasSuffix(arg, ".xml") {
			xmlFiles = append(xmlFiles, arg)
		} else if strings.HasSuffix(arg, ".pcap") || strings.HasSuffix(arg, ".pcapng") {
			pcapFiles = append(pcapFiles, arg)
		}
	}

	masterMap := model.NewNetworkMap()
	fmt.Println("--- Parsing Nmap files ---")
	for _, file := range xmlFiles {
		if err := nmap.MergeFromFile(file, masterMap); err != nil {
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
			if err := pcap.EnrichData(file, masterMap, globalSummary, eapolTracker, packetSources); err != nil {
				log.Printf("Warning: could not process pcap file %s: %v", file, err)
			}
		}
		fmt.Println("\n✅ Pcap enrichment complete.")
	}

	// Process handshakes after all pcaps are analyzed
	ProcessHandshakes(eapolTracker, masterMap, globalSummary, packetSources)

	fmt.Println("\n--- Performing Geolocation Lookups ---")
	geoCache := make(map[string]*model.GeoInfo)
	for _, host := range masterMap.Hosts {
		for _, comm := range host.Communications {
			if geoInfo, found := geoCache[comm.CounterpartIP]; found {
				comm.Geo = geoInfo
				continue
			}
			geoInfo, err := geoip.LookupIP(comm.CounterpartIP)
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

	// --- NEW: Improved MAC Vendor Lookup Logic ---
	fmt.Println("\n--- Performing MAC Vendor Lookups for Unidentified Devices ---")
	if len(globalSummary.UnidentifiedMACs) > 0 {
		totalMACs := len(globalSummary.UnidentifiedMACs)
		count := 0
		for mac := range globalSummary.UnidentifiedMACs {
			count++
			// Print a clean, updating progress counter
			fmt.Printf("\r  -> Looking up vendors... (%d/%d)", count, totalMACs)

			vendor, err := maclookup.LookupVendor(mac)
			if err != nil {
				// Don't log errors, just leave the vendor blank so the display logic handles it
				globalSummary.UnidentifiedMACs[mac] = ""
			} else {
				globalSummary.UnidentifiedMACs[mac] = vendor
			}

			// Add a 1-second delay to respect API rate limits
			time.Sleep(1 * time.Second)
		}
		fmt.Println("\n✅ MAC Vendor lookup complete.") // Print a newline to clean up the progress counter
	} else {
		fmt.Println("No unidentified devices to look up.")
	}

	// --- FINAL REPORT DISPLAY ---
	fmt.Println("\n\n===================================================")
	fmt.Println("          Host-Centric Network Report")
	fmt.Println("===================================================")

	var sortedHosts []*model.Host
	for _, host := range masterMap.Hosts {
		sortedHosts = append(sortedHosts, host)
	}
	sort.Slice(sortedHosts, func(i, j int) bool {
		return sortedHosts[i].MACAddress < sortedHosts[j].MACAddress
	})

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

		// --- RESTORED DNS LOOKUP DISPLAY ---
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

	// --- Display the Global Pcap Summary Report ---
	fmt.Println("\n\n===================================================")
	fmt.Println("            Global Pcap Summary")
	fmt.Println("===================================================")

	if len(globalSummary.UnidentifiedMACs) > 0 {
		fmt.Printf("\n--- Unidentified Devices (Seen in Pcap but not Nmap) ---\n")
		// --- NEW: Smart Display Logic ---
		for mac, vendor := range globalSummary.UnidentifiedMACs {
			// Check if we have a valid vendor name
			if vendor != "" && vendor != "Unknown Vendor" {
				parts := strings.Split(mac, ":")
				if len(parts) == 6 {
					// Format as Vendor-LastHalf
					lastHalf := strings.Join(parts[3:], ":")
					// Clean up long vendor names
					cleanVendor := strings.Split(vendor, ",")[0]
					fmt.Printf("  - %s-%s\n", cleanVendor, lastHalf)
				} else {
					// Fallback for unusually formatted MACs
					fmt.Printf("  - %s (%s)\n", mac, vendor)
				}
			} else {
				// If no valid vendor, just print the MAC
				fmt.Printf("  - %s\n", mac)
			}
		}
	}

	// --- ADVERTISING APs - THE FIX IS HERE ---
	if len(globalSummary.AdvertisedAPs) > 0 {
		fmt.Printf("\n--- Advertising Access Points (Seen via Beacons) ---\n")
		for ssid, apMACs := range globalSummary.AdvertisedAPs {
			var macList []string
			for mac := range apMACs {
				macList = append(macList, mac)
			}

			displaySSID := strings.TrimSpace(cleanString(ssid))
			if displaySSID == "" {
				displaySSID = "<Hidden SSID>"
			}
			fmt.Printf("  - SSID: %-25s | AP MAC(s): %s\n", displaySSID, strings.Join(macList, ", "))
		}
	}

	// --- PROBE REQUESTS - THE FIX IS HERE ---
	if len(globalSummary.AllProbeRequests) > 0 {
		fmt.Printf("\n--- Wi-Fi Probe Requests (Client Devices Searching) ---\n")
		for ssid, probers := range globalSummary.AllProbeRequests {
			count := len(probers)
			displaySSID := strings.TrimSpace(cleanString(ssid))
			if displaySSID == "" {
				displaySSID = "<Hidden SSID>"
			}
			fmt.Printf("  - SSID: %-25s | (Probed by %d unique device(s))\n", displaySSID, count)
		}
	}

	if len(globalSummary.ProtocolCounts) > 0 {
		fmt.Printf("\n--- Overall Protocol Statistics ---\n")
		for proto, count := range globalSummary.ProtocolCounts {
			fmt.Printf("  - %-25s : %d packets\n", proto, count)
		}
	}

	if len(globalSummary.CapturedHandshakes) > 0 {
		fmt.Println("\n\n===================================================")
		fmt.Println("     Captured Handshakes (for Cracking)")
		fmt.Println("===================================================")
		fmt.Println("\nInstructions: To use these handshakes with a tool like hashcat,")
		fmt.Println("copy the 'HCCAPX_HEX' data into a text file, then convert it back")
		fmt.Println("to a binary file. For example, in Linux/macOS, you can use:")
		fmt.Println("  xxd -r -p <your_hex_file> > handshake.hccapx")

		for _, hs := range globalSummary.CapturedHandshakes {
			fmt.Printf("\n--- Handshake for SSID: %s ---\n", hs.SSID)
			fmt.Printf("  Access Point MAC: %s\n", hs.APMAC)
			fmt.Printf("  Client MAC:       %s\n", hs.ClientMAC)
			fmt.Printf("  Pcap File:        %s\n", hs.PcapFile)
			fmt.Printf("  HCCAPX_HEX:       %s\n", hs.ToHCCAPXString())
		}
	}
}

// --- THIS FUNCTION IS NOW CORRECTED ---
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

			// --- THIS LOGIC IS NOW CORRECT ---
			if dot11.Flags.ToDS() && !dot11.Flags.FromDS() { // Frame from client to AP
				clientMAC = dot11.Address2.String()
				apMAC = dot11.Address1.String()
			} else if !dot11.Flags.ToDS() && dot11.Flags.FromDS() { // Frame from AP to client
				apMAC = dot11.Address2.String()
				clientMAC = dot11.Address1.String()
			}

			// A more reliable check for the 4 handshake messages would involve inspecting the EAPOL-Key data.
			// This simplified version checks for the presence of the different directions.
			if eapolLayer := pkt.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
				if dot11.Flags.ToDS() { // Messages 2 & 4 are from the client
					msg2 = true
					msg4 = true
				}
				if dot11.Flags.FromDS() { // Messages 1 & 3 are from the AP
					msg1 = true
					msg3 = true
				}
			}
		}

		state := "Partial"
		if msg1 && msg2 && msg3 && msg4 {
			state = "Full"
		}

		// Update or create hosts
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

			lastPacket := packets[len(packets)-1]
			pcapFile := packetSources[lastPacket]

			summary.CapturedHandshakes = append(summary.CapturedHandshakes, model.Handshake{
				ClientMAC: strings.ToUpper(clientMAC),
				APMAC:     strings.ToUpper(apMAC),
				SSID:      ssid,
				PcapFile:  pcapFile,
				HCCAPX:    []byte("SIMULATED_FULL_HANDSHAKE_FOR_" + sessionKey),
			})
		}
	}
}
