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

// EnrichData now takes both the host map and the global summary.
func EnrichData(filename string, networkMap *model.NetworkMap, summary *model.PcapSummary) error {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return err
	}
	defer handle.Close()

	fmt.Printf("  -> Performing full pcap analysis on %s...\n", filename)

	ipToHostKey := make(map[string]string)
	for key, host := range networkMap.Hosts {
		for ip := range host.IPv4Addresses {
			ipToHostKey[ip] = key
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Update the global summary with data from every packet
		updateGlobalSummary(packet, summary, networkMap)

		// Enrich known hosts (these functions now only do host-specific work)
		enrichHostIPData(packet, networkMap, ipToHostKey)
		enrichHostWifiData(packet, networkMap)
		enrichHostBehavior(packet, networkMap, ipToHostKey)
	}
	return nil
}

// --- NEW: updateGlobalSummary populates our new summary struct ---
func updateGlobalSummary(packet gopacket.Packet, summary *model.PcapSummary, networkMap *model.NetworkMap) {
	// 1. Log all protocols
	for _, layer := range packet.Layers() {
		protocolName := layer.LayerType().String()
		summary.ProtocolCounts[protocolName]++
	}

	// 2. Find unidentified MACs and global probe requests
	if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
		dot11, _ := dot11Layer.(*layers.Dot11)

		// Check Address 2 (Transmitter) as it's almost always present and is the source
		sourceMAC := strings.ToUpper(dot11.Address2.String())
		if _, known := networkMap.Hosts[sourceMAC]; !known && sourceMAC != "00:00:00:00:00:00" {
			summary.UnidentifiedMACs[sourceMAC] = true
		}

		// Check for probe requests from any device
		if dot11.Type == layers.Dot11TypeMgmtProbeReq {
			if ssid, err := getSSIDFromDot11(dot11); err == nil && ssid != "" && ssid != "<hidden or broadcast>" {
				summary.AllProbeRequests[ssid] = true
			}
		}
	}
}

// --- The following functions are now just for enriching known hosts ---

func enrichHostIPData(packet gopacket.Packet, networkMap *model.NetworkMap, ipToKey map[string]string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)
	sourceKey, found := ipToKey[ip.SrcIP.String()]
	if !found {
		return
	}
	host := networkMap.Hosts[sourceKey]
	comm, ok := host.Communications[ip.DstIP.String()]
	if !ok {
		comm = &model.Communication{CounterpartIP: ip.DstIP.String(), PacketCount: 0, Protocols: make(map[string]int)}
		host.Communications[ip.DstIP.String()] = comm
	}
	comm.PacketCount++
	comm.Protocols[ip.Protocol.String()]++
}

func enrichHostWifiData(packet gopacket.Packet, networkMap *model.NetworkMap) {
	if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
		dot11, _ := dot11Layer.(*layers.Dot11)
		key := strings.ToUpper(dot11.Address2.String())
		if host, found := networkMap.Hosts[key]; found {
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
			case layers.Dot11TypeMgmtAssociationReq, layers.Dot11TypeMgmtReassociationReq:
				host.Wifi.DeviceRole = "Client"
				host.Wifi.AssociatedAP = strings.ToUpper(dot11.Address1.String())
			}
		}
	}
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
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
	}
}

func enrichHostBehavior(packet gopacket.Packet, networkMap *model.NetworkMap, ipToKey map[string]string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)
	sourceKey, found := ipToKey[ip.SrcIP.String()]
	if !found {
		return
	}
	host := networkMap.Hosts[sourceKey]
	if host.Fingerprint == nil {
		return
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp.DstPort == 1900 {
			host.Fingerprint.BehavioralClues["Likely Media Device (SSDP/UPnP traffic)"] = true
		}
		if udp.DstPort == 5353 {
			host.Fingerprint.BehavioralClues["Service Discovery traffic detected (mDNS/Bonjour)"] = true
		}
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.DstPort == 445 {
			host.Fingerprint.BehavioralClues["Windows File Sharing or NAS detected (SMB traffic)"] = true
		}
	}
}

// (getSSIDFromDot11 helper function remains unchanged)
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
