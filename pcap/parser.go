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
func EnrichData(filename string, networkMap *model.NetworkMap, summary *model.PcapSummary, eapolTracker map[string][]gopacket.Packet, packetSources map[gopacket.Packet]string) error {
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
		// Keep track of which file this packet came from
		packetSources[packet] = filename

		updateGlobalSummary(packet, summary, networkMap)
		enrichHostIPData(packet, networkMap, ipToHostKey)
		enrichHostWifiData(packet, networkMap, eapolTracker)
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

// This function now just collects EAPOL packets, it does not determine state.
func enrichHostWifiData(packet gopacket.Packet, networkMap *model.NetworkMap, eapolTracker map[string][]gopacket.Packet) {
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return
	}
	dot11, _ := dot11Layer.(*layers.Dot11)

	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		addr1 := strings.ToUpper(dot11.Address1.String())
		addr2 := strings.ToUpper(dot11.Address2.String())
		addr3 := strings.ToUpper(dot11.Address3.String())

		var clientMAC, apMAC string

		// Determine client and AP based on ToDS/FromDS flags
		if dot11.Flags.ToDS() && !dot11.Flags.FromDS() {
			clientMAC = addr2
			apMAC = addr1
		} else if !dot11.Flags.ToDS() && dot11.Flags.FromDS() {
			clientMAC = addr1
			apMAC = addr2
		} else {
			// Could be management frames or other traffic, use Address 2 as a default key
			clientMAC = addr2
			apMAC = addr3
		}

		if clientMAC != "" && apMAC != "" {
			// Create a consistent key for the session by sorting MACs
			var key string
			if clientMAC < apMAC {
				key = fmt.Sprintf("%s-%s", clientMAC, apMAC)
			} else {
				key = fmt.Sprintf("%s-%s", apMAC, clientMAC)
			}
			// Store the entire EAPOL packet for later analysis
			eapolTracker[key] = append(eapolTracker[key], packet)
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
