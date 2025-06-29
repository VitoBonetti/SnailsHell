package model

// --- NEW: PcapSummary holds global data from all pcap files ---
type PcapSummary struct {
	// A set of MAC addresses seen in pcaps but not identified by Nmap.
	UnidentifiedMACs map[string]bool
	// A set of all SSIDs that any device was seen probing for.
	AllProbeRequests map[string]bool
	// A count of all packet types seen across all captures.
	ProtocolCounts map[string]int
}

// Fingerprint holds clues about the device's identity.
type Fingerprint struct {
	Vendor          string
	OperatingSystem string
	DeviceType      string
	BehavioralClues map[string]bool
}

// GeoInfo will store geolocation data for an IP address.
type GeoInfo struct {
	Country string
	City    string
	ISP     string
}

// WifiInfo holds all 802.11-specific data for a host.
type WifiInfo struct {
	DeviceRole    string
	AssociatedAP  string
	SSID          string
	ProbeRequests map[string]bool
	HasHandshake  bool
}

// Communication represents a single interaction between our host and another IP.
type Communication struct {
	CounterpartIP string
	PacketCount   int
	Protocols     map[string]int
	Geo           *GeoInfo
}

// NetworkMap is the top-level structure holding all network information.
type NetworkMap struct {
	Hosts map[string]*Host
}

// Host represents a single device on the network.
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
}

// Port represents a network port on a host.
type Port struct {
	ID       int
	Protocol string
	State    string
	Service  string
	Version  string
}

// Helper function to create a new, empty NetworkMap
func NewNetworkMap() *NetworkMap {
	return &NetworkMap{
		Hosts: make(map[string]*Host),
	}
}

// Helper function to create a new, empty PcapSummary
func NewPcapSummary() *PcapSummary {
	return &PcapSummary{
		UnidentifiedMACs: make(map[string]bool),
		AllProbeRequests: make(map[string]bool),
		ProtocolCounts:   make(map[string]int),
	}
}
