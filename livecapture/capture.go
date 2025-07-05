package livecapture

import (
	"context"
	"fmt"
	"gonetmap/model"
	"gonetmap/processing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// ListInterfaces finds and returns all available network interfaces.
func ListInterfaces() ([]pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("could not find devices: %w", err)
	}
	return devices, nil
}

// Start opens a network interface and processes packets in real-time.
func Start(ctx context.Context, interfaceName string, networkMap *model.NetworkMap, summary *model.PcapSummary) error {
	const (
		snapshotLen int32         = 1024
		promiscuous bool          = true
		timeout     time.Duration = -1 * time.Second
	)

	handle, err := pcap.OpenLive(interfaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		return fmt.Errorf("could not open live capture on interface %s: %w", interfaceName, err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return nil
			}
			processing.ProcessPacket(packet, networkMap, summary, "live capture")
		}
	}
}
