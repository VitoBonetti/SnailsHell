package processing

import (
	"encoding/binary"
	"gonetmap/model"
	"strings"

	"github.com/google/gopacket/layers"
)

// EAPOL Key Information field bits
const (
	keyInfoMIC bitmask = 1 << 8
	keyInfoACK bitmask = 1 << 7
)

type bitmask uint16

func (b bitmask) isSet(field uint16) bool {
	return (field & uint16(b)) != 0
}

// isMessage1 checks for EAPOL message 1 (ANonce from AP to client).
// Key ACK: 1, Key MIC: 0
func isMessage1(keyInfo uint16) bool {
	return keyInfoACK.isSet(keyInfo) && !keyInfoMIC.isSet(keyInfo)
}

// isMessage2 checks for EAPOL message 2 (SNonce from client to AP).
// Key ACK: 0, Key MIC: 1
func isMessage2(keyInfo uint16) bool {
	return !keyInfoACK.isSet(keyInfo) && keyInfoMIC.isSet(keyInfo)
}

// isMessage3 checks for EAPOL message 3 (GTK from AP to client).
// Key ACK: 1, Key MIC: 1, Install: 1 (not checked here for simplicity but is a factor)
func isMessage3(keyInfo uint16) bool {
	return keyInfoACK.isSet(keyInfo) && keyInfoMIC.isSet(keyInfo)
}

// isMessage4 checks for EAPOL message 4 (Confirmation from client to AP).
// Key ACK: 0, Key MIC: 1
func isMessage4(keyInfo uint16) bool {
	// Message 4 looks very similar to message 2, but it has a zero key length.
	// For simplicity, we'll treat any second message with ACK=0, MIC=1 as a potential message 4.
	// The presence of msg1, msg2, and msg3 is a stronger indicator.
	return !keyInfoACK.isSet(keyInfo) && keyInfoMIC.isSet(keyInfo)
}

// ProcessHandshakes analyzes captured EAPOL packets to identify WPA handshakes.
func ProcessHandshakes(networkMap *model.NetworkMap, summary *model.PcapSummary) {
	for sessionKey, packets := range summary.EapolTracker {
		macs := strings.Split(sessionKey, "-")
		if len(macs) != 2 {
			continue
		}

		// Flags to track which of the 4 handshake messages we've seen.
		var msg1, msg2, msg3, msg4 bool
		var apMAC, clientMAC string

		for _, pkt := range packets {
			dot11, _ := pkt.Layer(layers.LayerTypeDot11).(*layers.Dot11)

			// Identify AP and Client MACs from packet direction
			if dot11.Flags.ToDS() && !dot11.Flags.FromDS() {
				// Packet is going from a Station to an AP
				clientMAC = dot11.Address2.String()
				apMAC = dot11.Address1.String()
			} else if !dot11.Flags.ToDS() && dot11.Flags.FromDS() {
				// Packet is coming from an AP to a Station
				apMAC = dot11.Address2.String()
				clientMAC = dot11.Address1.String()
			}

			if eapolLayer := pkt.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
				eapol, _ := eapolLayer.(*layers.EAPOL)
				keyInfo := binary.BigEndian.Uint16(eapol.LayerPayload()[1:3])

				if isMessage1(keyInfo) {
					msg1 = true
				}
				if isMessage2(keyInfo) {
					// If we've already seen message 1, this must be message 2.
					// Otherwise, it could be a stray message 4.
					if msg1 {
						msg2 = true
					}
				}
				if isMessage3(keyInfo) {
					// Message 3 can only happen after 1 and 2.
					if msg1 && msg2 {
						msg3 = true
					}
				}
				if isMessage4(keyInfo) {
					// Message 4 can only happen after 1, 2, and 3.
					if msg1 && msg2 && msg3 {
						msg4 = true
					}
				}
			}
		}

		// Determine the handshake state
		state := "Partial"
		if msg1 && msg2 && msg3 && msg4 {
			state = "Full"
		} else if !msg1 && !msg2 && !msg3 && !msg4 {
			// If we didn't identify any messages, don't create a handshake entry
			continue
		}

		// Update host information with handshake details
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
			// Don't overwrite a "Full" state with a "Partial" one
			if host.Wifi.HandshakeState != "Full" {
				host.Wifi.HandshakeState = state
			}
			if addr == strings.ToUpper(apMAC) {
				host.Wifi.DeviceRole = "Access Point"
			} else {
				host.Wifi.DeviceRole = "Client"
			}
		}

		// Save full handshakes to the summary for database storage
		if state == "Full" {
			ssid := "UnknownSSID"
			// Try to find the SSID from the AP's host entry
			if ap, ok := networkMap.Hosts[strings.ToUpper(apMAC)]; ok && ap.Wifi != nil && ap.Wifi.SSID != "" {
				ssid = ap.Wifi.SSID
			}

			var handshakePacketsData []byte
			for _, pkt := range packets {
				// Only include EAPOL packets in the final data
				if pkt.Layer(layers.LayerTypeEAPOL) != nil {
					handshakePacketsData = append(handshakePacketsData, pkt.Data()...)
				}
			}

			// Get the source pcap file from the last packet in the session
			lastPacket := packets[len(packets)-1]
			pcapFile := summary.PacketSources[lastPacket]

			summary.CapturedHandshakes = append(summary.CapturedHandshakes, model.Handshake{
				ClientMAC:      strings.ToUpper(clientMAC),
				APMAC:          strings.ToUpper(apMAC),
				SSID:           ssid,
				PcapFile:       pcapFile,
				HCCAPX:         handshakePacketsData, // This contains the raw packet data for potential conversion
				HandshakeState: state,
			})
		}
	}
}
