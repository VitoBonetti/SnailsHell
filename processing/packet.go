package processing

import (
	"gonetmap/model"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ProcessPacket contains the core logic for analyzing a single packet.
// This version is corrected to process EAPOL handshakes before IP-based traffic.
func ProcessPacket(packet gopacket.Packet, networkMap *model.NetworkMap, summary *model.PcapSummary, sourceName string) {
	summary.TotalPackets++

	for _, layer := range packet.Layers() {
		summary.ProtocolCounts[layer.LayerType().String()]++
	}

	// --- EAPOL Handshake Processing (Layer 2) ---
	// This must happen BEFORE the IP address check, as handshake packets don't have IP addresses.
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		sessionKey := getSessionKey(packet)
		if sessionKey != "" {
			// Track the packet as part of a potential handshake session
			summary.EapolTracker[sessionKey] = append(summary.EapolTracker[sessionKey], packet)
			// Keep track of which pcap file the packet came from
			summary.PacketSources[packet] = sourceName
		}
	}

	// --- 802.11 Wireless Frame Processing ---
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer != nil {
		dot11, _ := dot11Layer.(*layers.Dot11)
		var mgmtPayload []byte
		// Extract SSIDs from various management frames
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

	// Get MAC addresses from Ethernet layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		srcMAC = eth.SrcMAC.String()
		dstMAC = eth.DstMAC.String()
	}

	// Get MAC addresses from 802.11 data frames that contain IP packets
	if dot11Layer != nil && (packet.Layer(layers.LayerTypeIPv4) != nil || packet.Layer(layers.LayerTypeIPv6) != nil) {
		dot11, _ := dot11Layer.(*layers.Dot11)
		// Determine MACs based on data flow direction (To/From Distribution System)
		switch {
		case dot11.Flags.ToDS() && !dot11.Flags.FromDS():
			srcMAC = dot11.Address2.String() // Station MAC
			dstMAC = dot11.Address1.String() // AP MAC
		case !dot11.Flags.ToDS() && dot11.Flags.FromDS():
			srcMAC = dot11.Address1.String() // AP MAC
			dstMAC = dot11.Address2.String() // Station MAC
		}
	}

	// Get IP addresses
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	}

	// If there is no IP traffic, we can't do host discovery, so we stop here.
	if srcIP == "" || dstIP == "" {
		return
	}

	srcIsLocal := isPrivateIP(net.ParseIP(srcIP))
	dstIsLocal := isPrivateIP(net.ParseIP(dstIP))

	// Skip packets between two public IPs
	if !srcIsLocal && !dstIsLocal {
		return
	}

	// Identify which MAC/IP is local vs remote
	var localMAC, localIP, remoteIP string
	if srcIsLocal {
		localMAC, localIP, remoteIP = srcMAC, srcIP, dstIP
	} else {
		localMAC, localIP, remoteIP = dstMAC, dstIP, srcIP
	}

	if localMAC == "" {
		return // Cannot create a host without a MAC address
	}

	// Update the network map with the discovered host
	host, found := networkMap.Hosts[strings.ToUpper(localMAC)]
	if !found {
		host = model.NewHost(strings.ToUpper(localMAC))
		host.DiscoveredBy = "Pcap"
		networkMap.Hosts[strings.ToUpper(localMAC)] = host
	}
	host.IPv4Addresses[localIP] = true

	// Track communication partners
	if _, ok := host.Communications[remoteIP]; !ok {
		host.Communications[remoteIP] = &model.Communication{CounterpartIP: remoteIP}
	}
	host.Communications[remoteIP].PacketCount++

	// Track DNS lookups
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		if dns.QR == false { // This is a query
			for _, q := range dns.Questions {
				host.DNSLookups[string(q.Name)] = true
			}
		}
	}
}

// getSSIDFromPayload extracts the SSID from an 802.11 management frame's payload.
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

// getSessionKey creates a unique key for a handshake session based on the two MAC addresses involved.
func getSessionKey(packet gopacket.Packet) string {
	if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
		dot11, _ := dot11Layer.(*layers.Dot11)
		addr1 := dot11.Address1.String()
		addr2 := dot11.Address2.String()
		// Sort the MACs alphabetically to ensure the key is consistent regardless of packet direction
		if strings.Compare(addr1, addr2) < 0 {
			return addr1 + "-" + addr2
		}
		return addr2 + "-" + addr1
	}
	return ""
}

// isPrivateIP checks if an IP address is within the private address ranges.
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
