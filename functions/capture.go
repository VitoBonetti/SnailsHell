package functions

import (
	"context"
	"fmt"
	"gonetmap/model"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// ListInterfaces finds and prints all available network interfaces.
func ListInterfaces() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("could not find devices: %w", err)
	}

	if len(devices) == 0 {
		fmt.Println("No network interfaces found. Make sure you have the necessary permissions.")
		return nil
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

	return nil
}

// StartLiveCapture opens a network interface and processes packets in real-time.
func StartLiveCapture(ctx context.Context, interfaceName string, networkMap *model.NetworkMap, summary *model.PcapSummary) error {
	// Configuration for the live capture
	const (
		snapshotLen int32         = 1024
		promiscuous bool          = true
		timeout     time.Duration = -1 * time.Second // Negative timeout for immediate packet delivery
	)

	handle, err := pcap.OpenLive(interfaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		return fmt.Errorf("could not open live capture on interface %s: %w", interfaceName, err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Process packets in a loop until the context is cancelled.
	for {
		select {
		case <-ctx.Done(): // If the context is cancelled (e.g., by Ctrl+C), stop the loop.
			return nil
		case packet, ok := <-packetSource.Packets():
			if !ok {
				// The packet source channel has been closed.
				return nil
			}
			// Process the captured packet.
			ProcessPacket(packet, networkMap, summary, "live capture")
		}
	}
}
