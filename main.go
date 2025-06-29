package main

import (
	"fmt"
	"gonetmap/model"
	"gonetmap/nmap"
	"gonetmap/pcap"
	"log"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <file1.xml> <file2.xml> ... <file1.pcap> <file2.pcap> ...")
		return
	}

	// --- 1. Sort input files ---
	var xmlFiles, pcapFiles []string
	for _, arg := range os.Args[1:] {
		if strings.HasSuffix(arg, ".xml") {
			xmlFiles = append(xmlFiles, arg)
		} else if strings.HasSuffix(arg, ".pcap") || strings.HasSuffix(arg, ".pcapng") {
			pcapFiles = append(pcapFiles, arg)
		}
	}

	if len(xmlFiles) == 0 {
		log.Fatal("No Nmap XML files provided.")
	}

	// --- 2. Create the master NetworkMap and merge all Nmap data ---
	masterMap := model.NewNetworkMap()
	fmt.Println("--- Parsing Nmap files ---")
	for _, file := range xmlFiles {
		if err := nmap.MergeFromFile(file, masterMap); err != nil {
			log.Printf("Warning: could not parse Nmap file %s: %v", file, err)
		}
	}
	fmt.Printf("\n✅ Nmap parsing complete. Found %d unique hosts.\n\n", len(masterMap.Hosts))

	// --- 3. Enrich the map with all Pcap data ---
	if len(pcapFiles) > 0 {
		fmt.Println("--- Enriching with Pcap files ---")
		for _, file := range pcapFiles {
			if err := pcap.EnrichWithPcapData(file, masterMap); err != nil {
				log.Printf("Warning: could not process pcap file %s: %v", file, err)
			}
		}
		fmt.Println("\n✅ Pcap enrichment complete.")
	}

	// --- 4. Display Final Results ---
	fmt.Println("\n===================================================")
	fmt.Println("          Consolidated Network Map")
	fmt.Println("===================================================")

	for key, host := range masterMap.Hosts {
		// Create a display-friendly list of IPs
		var ips []string
		for ip := range host.IPv4Addresses {
			ips = append(ips, ip)
		}

		fmt.Printf("\n--- Host MAC: %s ---\n", key)
		fmt.Printf("  IP Addresses: %s\n", strings.Join(ips, ", "))
		fmt.Printf("  Status: %s, Discovered: %s\n", host.Status, host.DiscoveredBy)

		if len(host.Ports) > 0 {
			fmt.Printf("  Nmap Ports:\n")
			for _, port := range host.Ports {
				fmt.Printf("    - Port %d/%s (%s): %s\n", port.ID, port.Protocol, port.State, port.Service+port.Version)
			}
		}

		if len(host.Communications) > 0 {
			fmt.Printf("  Pcap Communications:\n")
			for counterpartIP, comm := range host.Communications {
				fmt.Printf("    - Talked to %s (%d packets)\n", counterpartIP, comm.PacketCount)
			}
		}
	}
}
