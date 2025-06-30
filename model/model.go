package model

import "encoding/hex"

// --- NEW: Handshake struct to hold crackable data ---
type Handshake struct {
	ClientMAC string
	APMAC     string
	SSID      string
	PcapFile  string // The file where the handshake was found
	HCCAPX    []byte // The handshake data in hccapx format
}

// ToHCCAPXString converts the binary hccapx data to a hex string for easy display.
func (h *Handshake) ToHCCAPXString() string {
	return hex.EncodeToString(h.HCCAPX)
}

// --- NEW: Define categories for our findings ---
type FindingCategory string

const (
	CriticalFinding      FindingCategory = "Critical Vulnerabilities"
	PotentialFinding     FindingCategory = "Potential Weaknesses"
	InformationalFinding FindingCategory = "Informational Findings"
)

// --- NEW: Vulnerability holds details about a specific CVE or weakness. ---
type Vulnerability struct {
	PortID      int             // The port the vulnerability was found on (0 for host-level)
	CVE         string          // The CVE identifier, if available
	Description string          // The full description from the Nmap script
	State       string          // e.g., VULNERABLE, LIKELY VULNERABLE
	Category    FindingCategory // The category is now part of the struct.
}

// PcapSummary holds global data from all pcap files.
type PcapSummary struct {
	UnidentifiedMACs   map[string]string
	AllProbeRequests   map[string]map[string]bool
	AdvertisedAPs      map[string]map[string]bool
	ProtocolCounts     map[string]int
	CapturedHandshakes []Handshake
}

// (All other structs remain unchanged)
type Fingerprint struct {
	Vendor          string
	OperatingSystem string
	DeviceType      string
	BehavioralClues map[string]bool
}
type GeoInfo struct {
	Country string
	City    string
	ISP     string
}
type WifiInfo struct {
	DeviceRole     string
	AssociatedAP   string
	SSID           string
	ProbeRequests  map[string]bool
	HandshakeState string
}
type Communication struct {
	CounterpartIP string
	PacketCount   int
	Protocols     map[string]int
	Geo           *GeoInfo
}
type NetworkMap struct {
	Hosts map[string]*Host
}
type Host struct {
	IPv4Addresses  map[string]bool
	MACAddress     string
	Status         string
	Hostnames      []string
	Ports          map[int]Port
	Communications map[string]*Communication
	DiscoveredBy   string
	Wifi           *WifiInfo
	Fingerprint    *Fingerprint
	Findings       map[FindingCategory][]Vulnerability
	DNSLookups     map[string]bool
}
type Port struct {
	ID       int
	Protocol string
	State    string
	Service  string
	Version  string
}

func NewNetworkMap() *NetworkMap {
	return &NetworkMap{Hosts: make(map[string]*Host)}
}

// Update the helper to initialize the new and modified fields.
func NewPcapSummary() *PcapSummary {
	return &PcapSummary{
		UnidentifiedMACs:   make(map[string]string),
		AllProbeRequests:   make(map[string]map[string]bool),
		AdvertisedAPs:      make(map[string]map[string]bool),
		ProtocolCounts:     make(map[string]int),
		CapturedHandshakes: make([]Handshake, 0),
	}
}
