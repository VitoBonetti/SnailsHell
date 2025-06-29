package main

import (
	"fmt"
	"gonetmap/geoip"
	"gonetmap/model"
	"gonetmap/nmap"
	"gonetmap/pcap"
	"log"
	"os"
	"strings"
)

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

	if len(pcapFiles) > 0 {
		fmt.Println("--- Enriching with Pcap files ---")
		for _, file := range pcapFiles {
			if err := pcap.EnrichWithPcapData(file, masterMap); err != nil {
				log.Printf("Warning: could not process pcap file %s: %v", file, err)
			}
		}
		fmt.Println("\n✅ Pcap enrichment complete.")
	}

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

	// --- Display Final Results ---
	fmt.Println("\n===================================================")
	fmt.Println("          Consolidated & Enriched Network Map")
	fmt.Println("===================================================")
	for key, host := range masterMap.Hosts {
		var ips []string
		for ip := range host.IPv4Addresses {
			ips = append(ips, ip)
		}

		fmt.Printf("\n--- Host MAC: %s ---\n", key)
		fmt.Printf("  IP Addresses: %s\n", strings.Join(ips, ", "))
		fmt.Printf("  Status: %s\n", host.Status)

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

			// --- NEW: Display Behavioral Clues ---
			if len(host.Fingerprint.BehavioralClues) > 0 {
				fmt.Printf("    Behavioral Clues:\n")
				for clue := range host.Fingerprint.BehavioralClues {
					fmt.Printf("      - %s\n", clue)
				}
			}
		}

		// --- THE FIX IS HERE ---
		// Restored the missing display logic for Wi-Fi details.
		if host.Wifi != nil {
			fmt.Printf("  Wi-Fi Details:\n")
			if host.Wifi.DeviceRole != "" {
				fmt.Printf("    Role: %s\n", host.Wifi.DeviceRole)
			}
			if host.Wifi.DeviceRole == "Access Point" && host.Wifi.SSID != "" {
				fmt.Printf("    SSID: %s\n", host.Wifi.SSID)
			}
			if host.Wifi.DeviceRole == "Client" && host.Wifi.AssociatedAP != "" {
				fmt.Printf("    Connected to AP: %s\n", host.Wifi.AssociatedAP)
			}
			if len(host.Wifi.ProbeRequests) > 0 {
				var probes []string
				for ssid := range host.Wifi.ProbeRequests {
					probes = append(probes, ssid)
				}
				fmt.Printf("    Searching for SSIDs: %s\n", strings.Join(probes, ", "))
			}
			if host.Wifi.HasHandshake {
				fmt.Printf("    WPA Handshake Captured: Yes\n")
			}
		}

		// Restored the missing display logic for Nmap ports.
		if len(host.Ports) > 0 {
			fmt.Printf("  Nmap Ports:\n")
			for _, port := range host.Ports {
				versionInfo := port.Service
				if port.Version != " " {
					versionInfo += " " + port.Version
				}
				fmt.Printf("    - Port %d/%s (%s): %s\n", port.ID, port.Protocol, port.State, versionInfo)
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
	}
}
