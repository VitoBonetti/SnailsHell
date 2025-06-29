package main

import (
	"fmt"
	"gonetmap/model" // Using lowercase module name
	"gonetmap/nmap"  // Using lowercase module name
	"gonetmap/pcap"  // Using lowercase module name
	"log"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run . <path_to_nmap.xml> <path_to_capture.pcap>")
		return
	}
	nmapFilePath := os.Args[1]
	pcapFilePath := os.Args[2]

	// --- 1. Parse Nmap Data ---
	fmt.Printf("Attempting to parse Nmap data from: %s\n", nmapFilePath)
	networkMap, err := nmap.ParseFromFile(nmapFilePath)
	if err != nil {
		log.Fatalf("Error parsing nmap file: %v", err)
	}

	// --- THE FIX IS HERE ---
	// We iterate through the hosts from the parser and initialize their
	// communication fields. The loop variable 'host' is already a pointer.
	for _, host := range networkMap.Hosts {
		host.DiscoveredBy = "Nmap"
		host.Communications = make(map[string]*model.Communication)
	}
	fmt.Printf("\n✅ Successfully parsed Nmap data. Found %d hosts.\n", len(networkMap.Hosts))

	// --- 2. Enrich with Pcap Data ---
	if err := pcap.EnrichWithPcapData(pcapFilePath, networkMap); err != nil {
		log.Fatalf("Error processing pcap file: %v", err)
	}

	// --- 3. Display Final Results ---
	fmt.Println("\n===================================================")
	fmt.Println("            Enriched Network Map")
	fmt.Println("===================================================")

	for _, host := range networkMap.Hosts {
		fmt.Printf("\n--- Host: %s (Found by: %s) ---\n", host.IPv4Address, host.DiscoveredBy)
		fmt.Printf("  Status: %s, MAC: %s\n", host.Status, host.MACAddress)

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
				fmt.Printf("    - Talked to %s (%d packets, protocol: %s)\n", counterpartIP, comm.PacketCount, comm.Protocol)
			}
		} else {
			fmt.Printf("  Pcap Communications: None observed.\n")
		}
	}
}
