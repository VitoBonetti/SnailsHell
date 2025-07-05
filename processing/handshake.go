package processing

import (
	"gonetmap/model"
	"strings"

	"github.com/google/gopacket/layers"
)

// ProcessHandshakes analyzes captured EAPOL packets to identify WPA handshakes.
func ProcessHandshakes(networkMap *model.NetworkMap, summary *model.PcapSummary) {
	for sessionKey, packets := range summary.EapolTracker {
		macs := strings.Split(sessionKey, "-")
		if len(macs) != 2 {
			continue
		}

		msg1, msg2, msg3, msg4 := false, false, false, false
		var apMAC, clientMAC string

		for _, pkt := range packets {
			dot11, _ := pkt.Layer(layers.LayerTypeDot11).(*layers.Dot11)
			if dot11.Flags.ToDS() && !dot11.Flags.FromDS() {
				clientMAC = dot11.Address2.String()
				apMAC = dot11.Address1.String()
			} else if !dot11.Flags.ToDS() && dot11.Flags.FromDS() {
				apMAC = dot11.Address2.String()
				clientMAC = dot11.Address1.String()
			}
			if eapolLayer := pkt.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
				if dot11.Flags.ToDS() {
					msg2, msg4 = true, true
				}
				if dot11.Flags.FromDS() {
					msg1, msg3 = true, true
				}
			}
		}

		state := "Partial"
		if msg1 && msg2 && msg3 && msg4 {
			state = "Full"
		}

		for _, addr := range []string{strings.ToUpper(apMAC), strings.ToUpper(clientMAC)} {
			if addr == "" {
				continue
			}
			host, found := networkMap.Hosts[addr]
			if !found {
				host = model.NewHost(addr)
				host.DiscoveredBy = "Pcap (Handshake)"
				networkMap.Hosts[addr] = host
			}
			if host.Wifi == nil {
				host.Wifi = &model.WifiInfo{ProbeRequests: make(map[string]bool)}
			}
			host.Wifi.HandshakeState = state
			if addr == strings.ToUpper(apMAC) {
				host.Wifi.DeviceRole = "Access Point"
			} else {
				host.Wifi.DeviceRole = "Client"
			}
		}

		if state == "Full" {
			ssid := "UnknownSSID"
			if ap, ok := networkMap.Hosts[strings.ToUpper(apMAC)]; ok && ap.Wifi != nil && ap.Wifi.SSID != "" {
				ssid = ap.Wifi.SSID
			}

			var realHandshakeData []byte
			for _, pkt := range packets {
				if eapolLayer := pkt.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
					realHandshakeData = append(realHandshakeData, pkt.Data()...)
				}
			}

			lastPacket := packets[len(packets)-1]
			pcapFile := summary.PacketSources[lastPacket]

			summary.CapturedHandshakes = append(summary.CapturedHandshakes, model.Handshake{
				ClientMAC:      strings.ToUpper(clientMAC),
				APMAC:          strings.ToUpper(apMAC),
				SSID:           ssid,
				PcapFile:       pcapFile,
				HCCAPX:         realHandshakeData,
				HandshakeState: state,
			})
		}
	}
}
