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

// (The main EnrichData function is unchanged)
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
		updateGlobalSummary(packet, summary, networkMap)
		enrichHostIPData(packet, networkMap, ipToHostKey)
		enrichHostWifiData(packet, networkMap)
		enrichHostBehavior(packet, networkMap, ipToHostKey)
		enrichHostDNS(packet, networkMap, ipToHostKey)
	}
	return nil
}

func enrichHostDNS(packet gopacket.Packet, networkMap *model.NetworkMap, ipToKey map[string]string) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)

	if udp.DstPort != 53 {
		return
	}

	dnsPacket := gopacket.NewPacket(udp.Payload, layers.LayerTypeDNS, gopacket.Default)
	if dnsLayer := dnsPacket.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)

		if dns.QR {
			return
		}

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

		for _, q := range dns.Questions {
			host.DNSLookups[string(q.Name)] = true
		}
	}
}

func updateGlobalSummary(packet gopacket.Packet, summary *model.PcapSummary, networkMap *model.NetworkMap) {
	for _, layer := range packet.Layers() {
		summary.ProtocolCounts[layer.LayerType().String()]++
	}

	if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
		dot11, _ := dot11Layer.(*layers.Dot11)
		sourceMAC := strings.ToUpper(dot11.Address2.String())

		if _, known := networkMap.Hosts[sourceMAC]; !known && sourceMAC != "00:00:00:00:00:00" && sourceMAC != "" {
			if _, exists := summary.UnidentifiedMACs[sourceMAC]; !exists {
				summary.UnidentifiedMACs[sourceMAC] = ""
			}
		}

		if dot11.Type == layers.Dot11TypeMgmtBeacon {
			if ssid, err := getSSIDFromDot11(dot11); err == nil && ssid != "" && ssid != "<hidden or broadcast>" {
				if _, ok := summary.AdvertisedAPs[ssid]; !ok {
					summary.AdvertisedAPs[ssid] = make(map[string]bool)
				}
				summary.AdvertisedAPs[ssid][sourceMAC] = true
			}
		}

		if dot11.Type == layers.Dot11TypeMgmtProbeReq {
			if ssid, err := getSSIDFromDot11(dot11); err == nil && ssid != "" && ssid != "<hidden or broadcast>" {
				if _, ok := summary.AllProbeRequests[ssid]; !ok {
					summary.AllProbeRequests[ssid] = make(map[string]bool)
				}
				summary.AllProbeRequests[ssid][sourceMAC] = true
			}
		}
	}
}

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

	// --- NEW AND IMPROVED HANDSHAKE DETECTION LOGIC ---
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
			dot11, _ := dot11Layer.(*layers.Dot11)

			// EAPOL frames involve two main parties. Let's check the relevant address fields.
			// Address1: Destination, Address2: Source
			addrs := []string{
				strings.ToUpper(dot11.Address1.String()),
				strings.ToUpper(dot11.Address2.String()),
			}

			for _, addr := range addrs {
				if addr == "" || addr == "00:00:00:00:00:00" {
					continue
				}

				// Check if the host is already known
				host, found := networkMap.Hosts[addr]
				if !found {
					// If not, create a new host entry for it
					host = &model.Host{
						MACAddress:     addr,
						DiscoveredBy:   "Pcap (Handshake)",
						Status:         "Unknown",
						IPv4Addresses:  make(map[string]bool),
						Ports:          make(map[int]model.Port),
						Communications: make(map[string]*model.Communication),
						Findings:       make(map[model.FindingCategory][]model.Vulnerability),
						DNSLookups:     make(map[string]bool),
					}
					networkMap.Hosts[addr] = host
				}

				// Now, ensure WifiInfo exists and flag the handshake
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
