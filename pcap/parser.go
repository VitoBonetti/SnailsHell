package pcap

import (
	"fmt"
	"gonetmap/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// EnrichWithPcapData reads a pcap file and populates the communication data
// for the hosts found in the provided network map.
func EnrichWithPcapData(filename string, networkMap *model.NetworkMap) error {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return fmt.Errorf("error opening pcap file: %w", err)
	}
	defer handle.Close()

	fmt.Println("\n🔎 Starting pcap analysis to enrich host data...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// We only care about packets with network-layer information (IP)
		networkLayer := packet.Layer(layers.LayerTypeIPv4)
		if networkLayer == nil {
			continue
		}

		// Type-assert the layer to get the actual IPv4 data
		ip, _ := networkLayer.(*layers.IPv4)

		srcIP := ip.SrcIP.String()
		dstIP := ip.DstIP.String()

		// --- Enrichment Logic ---
		processCommunication(srcIP, dstIP, ip.Protocol.String(), networkMap)
		processCommunication(dstIP, srcIP, ip.Protocol.String(), networkMap)
	}

	fmt.Println("✅ Pcap analysis complete.")
	return nil
}

// processCommunication updates the communication map for a given source IP.
func processCommunication(source, destination, protocol string, networkMap *model.NetworkMap) {
	// Check if the source of the packet is one of our known hosts
	if host, found := networkMap.Hosts[source]; found {
		// Check if we've already recorded a communication with this destination
		if comm, ok := host.Communications[destination]; ok {
			// If so, just increment the packet count
			comm.PacketCount++
		} else {
			// Otherwise, create a new communication entry
			host.Communications[destination] = &model.Communication{
				CounterpartIP: destination,
				PacketCount:   1,
				Protocol:      protocol,
			}
		}
	}
	// Note: In a future step, we could add any IP not found in the map
	// as a newly "Discovered" host. For now, we only enrich existing hosts.
}
