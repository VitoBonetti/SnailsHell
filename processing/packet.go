package processing

import (
	"SnailsHell/model"
	"net"
	"regexp"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	// Regex for finding API keys (prefixed with "apikey", "key", "token", etc.)
	apiKeyRegex = regexp.MustCompile(`(?i)(apikey|key|token|secret|password)[\s="':]+([a-zA-Z0-9\-_]{20,})`)
	// Regex for finding Bearer tokens
	bearerTokenRegex = regexp.MustCompile(`(?i)Authorization: Bearer ([a-zA-Z0-9\-_.]+)`)
)

// ProcessPacket contains the core logic for analyzing a single packet.
func ProcessPacket(packet gopacket.Packet, networkMap *model.NetworkMap, summary *model.PcapSummary, sourceName string) {
	summary.TotalPackets++

	for _, layer := range packet.Layers() {
		summary.ProtocolCounts[layer.LayerType().String()]++
	}

	// --- EAPOL Handshake Processing (Layer 2) ---
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		sessionKey := getSessionKey(packet)
		if sessionKey != "" {
			summary.EapolTracker[sessionKey] = append(summary.EapolTracker[sessionKey], packet)
			summary.PacketSources[packet] = sourceName
		}
	}

	// --- 802.11 Wireless Frame Processing ---
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer != nil {
		dot11, _ := dot11Layer.(*layers.Dot11)
		var mgmtPayload []byte
		if beaconLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon); beaconLayer != nil {
			mgmtPayload = beaconLayer.LayerPayload()
			ssid := getSSIDFromPayload(mgmtPayload)
			if _, ok := summary.AdvertisedAPs[ssid]; !ok {
				summary.AdvertisedAPs[ssid] = make(map[string]bool)
			}
			summary.AdvertisedAPs[ssid][dot11.Address2.String()] = true
		} else if probeRespLayer := packet.Layer(layers.LayerTypeDot11MgmtProbeResp); probeRespLayer != nil {
			mgmtPayload = probeRespLayer.LayerPayload()
			ssid := getSSIDFromPayload(mgmtPayload)
			if _, ok := summary.AdvertisedAPs[ssid]; !ok {
				summary.AdvertisedAPs[ssid] = make(map[string]bool)
			}
			summary.AdvertisedAPs[ssid][dot11.Address2.String()] = true
		} else if probeReqLayer := packet.Layer(layers.LayerTypeDot11MgmtProbeReq); probeReqLayer != nil {
			mgmtPayload = probeReqLayer.LayerPayload()
			ssid := getSSIDFromPayload(mgmtPayload)
			if _, ok := summary.AllProbeRequests[ssid]; !ok {
				summary.AllProbeRequests[ssid] = make(map[string]bool)
			}
			summary.AllProbeRequests[ssid][dot11.Address2.String()] = true
		}
	}

	// --- IP-Based Traffic Processing (Layer 3) ---

	var srcMAC, dstMAC, srcIP, dstIP string

	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		srcMAC = eth.SrcMAC.String()
		dstMAC = eth.DstMAC.String()
	}

	if dot11Layer != nil && (packet.Layer(layers.LayerTypeIPv4) != nil || packet.Layer(layers.LayerTypeIPv6) != nil) {
		dot11, _ := dot11Layer.(*layers.Dot11)
		switch {
		case dot11.Flags.ToDS() && !dot11.Flags.FromDS():
			srcMAC = dot11.Address2.String()
			dstMAC = dot11.Address1.String()
		case !dot11.Flags.ToDS() && dot11.Flags.FromDS():
			srcMAC = dot11.Address1.String()
			dstMAC = dot11.Address2.String()
		}
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	}

	if srcIP == "" || dstIP == "" {
		return
	}

	srcIsLocal := isPrivateIP(net.ParseIP(srcIP))
	dstIsLocal := isPrivateIP(net.ParseIP(dstIP))

	if !srcIsLocal && !dstIsLocal {
		return
	}

	var localMAC, localIP, remoteIP string
	if srcIsLocal {
		localMAC, localIP, remoteIP = srcMAC, srcIP, dstIP
	} else {
		localMAC, localIP, remoteIP = dstMAC, dstIP, srcIP
	}

	if localMAC == "" {
		return
	}

	host, found := networkMap.Hosts[strings.ToUpper(localMAC)]
	if !found {
		host = model.NewHost(strings.ToUpper(localMAC))
		host.DiscoveredBy = "Pcap"
		networkMap.Hosts[strings.ToUpper(localMAC)] = host
	}
	host.IPv4Addresses[localIP] = true

	if _, ok := host.Communications[remoteIP]; !ok {
		host.Communications[remoteIP] = &model.Communication{CounterpartIP: remoteIP}
	}
	host.Communications[remoteIP].PacketCount++

	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		if dns.QR == false {
			for _, q := range dns.Questions {
				host.DNSLookups[string(q.Name)] = true
			}
		}
	}

	// Check for secrets in the application layer payload
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		checkForSecrets(appLayer.Payload(), host.MACAddress, remoteIP, summary, sourceName)
	}
}

func checkForSecrets(payload []byte, hostMAC, remoteIP string, summary *model.PcapSummary, pcapFile string) {
	payloadStr := string(payload)

	// Check for API keys
	matches := apiKeyRegex.FindAllStringSubmatch(payloadStr, -1)
	for _, match := range matches {
		if len(match) > 2 {
			cred := model.Credential{
				HostMAC:  hostMAC,
				Endpoint: remoteIP,
				Type:     "API Key/Token",
				Value:    match[2],
				PcapFile: pcapFile,
			}
			summary.Credentials = append(summary.Credentials, cred)
		}
	}

	// Check for Bearer tokens
	matches = bearerTokenRegex.FindAllStringSubmatch(payloadStr, -1)
	for _, match := range matches {
		if len(match) > 1 {
			cred := model.Credential{
				HostMAC:  hostMAC,
				Endpoint: remoteIP,
				Type:     "Bearer Token",
				Value:    match[1],
				PcapFile: pcapFile,
			}
			summary.Credentials = append(summary.Credentials, cred)
		}
	}
}

func getSSIDFromPayload(payload []byte) string {
	for len(payload) >= 2 {
		id := layers.Dot11InformationElementID(payload[0])
		length := int(payload[1])

		if len(payload) < 2+length {
			return ""
		}

		if id == layers.Dot11InformationElementIDSSID {
			return string(payload[2 : 2+length])
		}

		payload = payload[2+length:]
	}
	return ""
}

func getSessionKey(packet gopacket.Packet) string {
	if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
		dot11, _ := dot11Layer.(*layers.Dot11)
		addr1 := dot11.Address1.String()
		addr2 := dot11.Address2.String()
		if strings.Compare(addr1, addr2) < 0 {
			return addr1 + "-" + addr2
		}
		return addr2 + "-" + addr1
	}
	return ""
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	privateIPBlocks := []*net.IPNet{
		{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)},
		{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)},
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
