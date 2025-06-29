package pcap

import (
	"bytes"
	"fmt"
	"gonetmap/model"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// EnrichWithPcapData now inspects both IP and 802.11 layers.
func EnrichWithPcapData(filename string, networkMap *model.NetworkMap) error {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return err
	}
	defer handle.Close()

	fmt.Printf("  -> Enriching with deep packet analysis from %s...\n", filename)

	ipToHostKey := make(map[string]string)
	for key, host := range networkMap.Hosts {
		for ip := range host.IPv4Addresses {
			ipToHostKey[ip] = key
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// --- Standard IP Communication (from before) ---
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			processIPCommunication(ip, networkMap, ipToHostKey)
		}

		// --- Wi-Fi Frame Analysis ---
		if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
			dot11, _ := dot11Layer.(*layers.Dot11)
			processDot11Frame(dot11, networkMap)
		}

		// --- Handshake Detection ---
		if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
			processEAPOL(packet, networkMap)
		}
	}
	return nil
}

// processDot11Frame analyzes 802.11 management frames.
func processDot11Frame(dot11 *layers.Dot11, networkMap *model.NetworkMap) {
	key := strings.ToUpper(dot11.Address2.String())
	if key == "" {
		return
	}

	host, found := networkMap.Hosts[key]
	if !found {
		return
	}
	if host.Wifi == nil {
		host.Wifi = &model.WifiInfo{ProbeRequests: make(map[string]bool)}
	}

	switch dot11.Type {
	case layers.Dot11TypeMgmtBeacon:
		host.Wifi.DeviceRole = "Access Point"
		if ssid, err := getSSIDFromDot11(dot11); err == nil {
			host.Wifi.SSID = ssid
		}

	case layers.Dot11TypeMgmtProbeReq:
		host.Wifi.DeviceRole = "Client"
		if ssid, err := getSSIDFromDot11(dot11); err == nil && ssid != "" {
			host.Wifi.ProbeRequests[ssid] = true
		}

	// --- THE FIX IS HERE ---
	// Using the older, longer, and more compatible constant names.
	case layers.Dot11TypeMgmtAssociationReq, layers.Dot11TypeMgmtReassociationReq:
		host.Wifi.DeviceRole = "Client"
		host.Wifi.AssociatedAP = strings.ToUpper(dot11.Address1.String())
	}
}

// processEAPOL detects WPA handshakes.
func processEAPOL(packet gopacket.Packet, networkMap *model.NetworkMap) {
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return
	}
	dot11, _ := dot11Layer.(*layers.Dot11)

	addr1 := strings.ToUpper(dot11.Address1.String())
	addr2 := strings.ToUpper(dot11.Address2.String())

	if host, ok := networkMap.Hosts[addr1]; ok {
		if host.Wifi == nil {
			host.Wifi = &model.WifiInfo{ProbeRequests: make(map[string]bool)}
		}
		host.Wifi.HasHandshake = true
	}
	if host, ok := networkMap.Hosts[addr2]; ok {
		if host.Wifi == nil {
			host.Wifi = &model.WifiInfo{ProbeRequests: make(map[string]bool)}
		}
		host.Wifi.HasHandshake = true
	}
}

// Helper to decode SSID from information elements by manually parsing the layer payload.
func getSSIDFromDot11(dot11 *layers.Dot11) (string, error) {
	payload := dot11.LayerPayload()
	for len(payload) >= 2 {
		id := layers.Dot11InformationElementID(payload[0])
		length := int(payload[1])

		if len(payload) < 2+length {
			return "", fmt.Errorf("malformed IE")
		}

		if id == layers.Dot11InformationElementIDSSID {
			info := payload[2 : 2+length]
			if len(info) == 0 || (len(info) > 0 && bytes.Contains(info, []byte{0x00})) {
				return "<hidden or broadcast>", nil
			}
			return string(info), nil
		}
		payload = payload[2+length:]
	}

	return "", fmt.Errorf("SSID not found")
}

// processIPCommunication handles the standard IP traffic analysis.
func processIPCommunication(ip *layers.IPv4, networkMap *model.NetworkMap, ipToKey map[string]string) {
	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()

	sourceKey, found := ipToKey[srcIP]
	if !found {
		return
	}
	host := networkMap.Hosts[sourceKey]

	comm, ok := host.Communications[dstIP]
	if !ok {
		comm = &model.Communication{
			CounterpartIP: dstIP,
			PacketCount:   0,
			Protocols:     make(map[string]int),
		}
		host.Communications[dstIP] = comm
	}
	comm.PacketCount++
	comm.Protocols[ip.Protocol.String()]++
}
