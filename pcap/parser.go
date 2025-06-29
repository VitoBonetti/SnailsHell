package pcap

import (
	"fmt"
	"gonetmap/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// EnrichWithPcapData can now be called multiple times for multiple files.
func EnrichWithPcapData(filename string, networkMap *model.NetworkMap) error {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return err
	}
	defer handle.Close()

	fmt.Printf("  -> Enriching with data from %s...\n", filename)

	// Create a quick lookup map from IP to MAC key for fast enrichment
	ipToHostKey := make(map[string]string)
	for key, host := range networkMap.Hosts {
		for ip := range host.IPv4Addresses {
			ipToHostKey[ip] = key
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		networkLayer := packet.Layer(layers.LayerTypeIPv4)
		if networkLayer == nil {
			continue
		}
		ip, _ := networkLayer.(*layers.IPv4)
		srcIP := ip.SrcIP.String()
		dstIP := ip.DstIP.String()

		processCommunication(srcIP, dstIP, ip.Protocol.String(), networkMap, ipToHostKey)
		processCommunication(dstIP, srcIP, ip.Protocol.String(), networkMap, ipToHostKey)
	}
	return nil
}

func processCommunication(source, destination, protocol string, networkMap *model.NetworkMap, ipToKey map[string]string) {
	// Find the host's main key (MAC address) using its IP from the packet
	hostKey, found := ipToKey[source]
	if !found {
		return // We only care about enriching hosts we already know from Nmap
	}

	host := networkMap.Hosts[hostKey]

	comm, ok := host.Communications[destination]
	if !ok {
		comm = &model.Communication{
			CounterpartIP: destination,
			PacketCount:   0,
			Protocols:     make(map[string]int),
		}
		host.Communications[destination] = comm
	}

	comm.PacketCount++
	comm.Protocols[protocol]++
}
