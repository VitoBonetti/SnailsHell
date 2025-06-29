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

// EnrichWithPcapData now calls our new behavioral analysis function.
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
		processIPCommunication(packet, networkMap, ipToHostKey)
		processWifiFrames(packet, networkMap)
		processBehavioralAnalysis(packet, networkMap, ipToHostKey)
	}
	return nil
}

// processBehavioralAnalysis inspects traffic for clues
func processBehavioralAnalysis(packet gopacket.Packet, networkMap *model.NetworkMap, ipToKey map[string]string) {
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
		switch udp.DstPort {
		case 1900:
			host.Fingerprint.BehavioralClues["Likely Media Device (SSDP/UPnP traffic)"] = true
		case 5353:
			// --- THE IMPROVEMENT IS HERE ---
			// This new description is more accurate and less brand-specific.
			host.Fingerprint.BehavioralClues["Service Discovery traffic detected (mDNS/Bonjour)"] = true
		}
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		switch tcp.DstPort {
		case 445:
			host.Fingerprint.BehavioralClues["Windows File Sharing or NAS detected (SMB traffic)"] = true
		}
	}
}

// Renamed from processIPCommunication for clarity
func processIPCommunication(packet gopacket.Packet, networkMap *model.NetworkMap, ipToKey map[string]string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

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

// Renamed from a mix of functions to one clear function
func processWifiFrames(packet gopacket.Packet, networkMap *model.NetworkMap) {
	// Wi-Fi Frame Analysis
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
	// Handshake Detection
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
