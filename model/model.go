package model

import (
	"encoding/hex"

	"github.com/google/gopacket"
)

// NetworkMap is the master data structure that holds all discovered hosts.
type NetworkMap struct {
	Hosts map[string]*Host `json:"hosts"` // Keyed by MAC Address
}

// NewNetworkMap creates an initialized NetworkMap.
func NewNetworkMap() *NetworkMap {
	return &NetworkMap{
		Hosts: make(map[string]*Host),
	}
}

// Host represents a single device on the network.
type Host struct {
	ID             int64                               `json:"id"`
	MACAddress     string                              `json:"mac_address"`
	IPv4Addresses  map[string]bool                     `json:"ipv4_addresses"`
	Status         string                              `json:"status"` // e.g., "up" or "down"
	DiscoveredBy   string                              `json:"discovered_by"`
	Ports          map[int]Port                        `json:"ports"`
	Fingerprint    *Fingerprint                        `json:"fingerprint"`
	Communications map[string]*Communication           `json:"communications"` // Keyed by counterpart IP
	DNSLookups     map[string]bool                     `json:"dns_lookups"`
	Findings       map[FindingCategory][]Vulnerability `json:"findings"`
	Wifi           *WifiInfo                           `json:"wifi,omitempty"`
}

// NewHost creates an initialized Host.
func NewHost(mac string) *Host {
	return &Host{
		MACAddress:     mac,
		IPv4Addresses:  make(map[string]bool),
		Ports:          make(map[int]Port),
		Communications: make(map[string]*Communication),
		Findings:       make(map[FindingCategory][]Vulnerability),
		DNSLookups:     make(map[string]bool),
		Fingerprint:    &Fingerprint{BehavioralClues: make(map[string]bool)},
		Wifi:           &WifiInfo{ProbeRequests: make(map[string]bool)},
	}
}

// Port represents a TCP/UDP port on a host.
type Port struct {
	ID       int    `json:"id"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version"`
}

// Fingerprint holds OS and device type information.
type Fingerprint struct {
	OperatingSystem string          `json:"operating_system"`
	DeviceType      string          `json:"device_type"`
	Vendor          string          `json:"vendor"`
	BehavioralClues map[string]bool `json:"behavioral_clues"`
}

// Communication represents a conversation between a local host and a remote IP.
type Communication struct {
	CounterpartIP string   `json:"counterpart_ip"`
	PacketCount   int      `json:"packet_count"`
	Geo           *GeoInfo `json:"geo,omitempty"`
}

// GeoInfo holds geolocation data for an IP address.
type GeoInfo struct {
	Country string `json:"country"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
}

// FindingCategory defines the severity of a vulnerability.
type FindingCategory string

const (
	CriticalFinding      FindingCategory = "Critical"
	PotentialFinding     FindingCategory = "Potential"
	InformationalFinding FindingCategory = "Informational"
)

// Vulnerability holds details about a single finding.
type Vulnerability struct {
	CVE         string          `json:"cve"`
	Description string          `json:"description"`
	State       string          `json:"state"`
	Category    FindingCategory `json:"category"`
	PortID      int             `json:"port_id,omitempty"`
}

// WifiInfo holds 802.11-specific details.
type WifiInfo struct {
	DeviceRole     string          `json:"device_role"` // "Access Point" or "Client"
	SSID           string          `json:"ssid,omitempty"`
	AssociatedAP   string          `json:"associated_ap,omitempty"`
	ProbeRequests  map[string]bool `json:"probe_requests,omitempty"`
	HandshakeState string          `json:"handshake_state,omitempty"` // "Full", "Partial"
}

// PcapSummary holds global statistics from pcap processing.
type PcapSummary struct {
	TotalPackets       int
	ProtocolCounts     map[string]int
	AdvertisedAPs      map[string]map[string]bool
	AllProbeRequests   map[string]map[string]bool
	UnidentifiedMACs   map[string]string
	CapturedHandshakes []Handshake
	Credentials        []Credential
	EapolTracker       map[string][]gopacket.Packet `json:"-"`
	PacketSources      map[gopacket.Packet]string   `json:"-"`
}

// NewPcapSummary creates an initialized PcapSummary.
func NewPcapSummary() *PcapSummary {
	return &PcapSummary{
		ProtocolCounts:     make(map[string]int),
		AdvertisedAPs:      make(map[string]map[string]bool),
		AllProbeRequests:   make(map[string]map[string]bool),
		UnidentifiedMACs:   make(map[string]string),
		CapturedHandshakes: []Handshake{},
		Credentials:        []Credential{},
		EapolTracker:       make(map[string][]gopacket.Packet),
		PacketSources:      make(map[gopacket.Packet]string),
	}
}

// Handshake holds data required for WPA handshake cracking.
type Handshake struct {
	ClientMAC      string
	APMAC          string
	SSID           string
	PcapFile       string
	HCCAPX         []byte
	HandshakeState string
}

// ToHCCAPXString converts the handshake data to a hex string for display.
func (h *Handshake) ToHCCAPXString() string {
	return hex.EncodeToString(h.HCCAPX)
}

// ReportHandshakeInfo is a struct for displaying handshakes in the UI and reports.
type ReportHandshakeInfo struct {
	ID        int64
	APMAC     string
	ClientMAC string
	SSID      string
	PcapFile  string
	HCCAPX    string // The hex-encoded data for display
}

// Credential represents a secret found in traffic.
type Credential struct {
	ID         int64
	HostID     int64
	HostMAC    string
	Endpoint   string
	Type       string
	Value      string
	CapturedAt string
	CampaignID int64
	PcapFile   string
}
