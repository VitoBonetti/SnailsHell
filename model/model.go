package model

// PcapSummary holds global data from all pcap files.
type PcapSummary struct {
	UnidentifiedMACs map[string]string
	// Key: SSID, Value: a set of MACs that probed for it.
	AllProbeRequests map[string]map[string]bool
	// --- THE FIX IS HERE ---
	// Changed from map[string]string to handle multiple APs for one SSID.
	// Key: SSID, Value: a set of AP MACs advertising it.
	AdvertisedAPs  map[string]map[string]bool
	ProtocolCounts map[string]int
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
	DeviceRole    string
	AssociatedAP  string
	SSID          string
	ProbeRequests map[string]bool
	HasHandshake  bool
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
		UnidentifiedMACs: make(map[string]string),
		AllProbeRequests: make(map[string]map[string]bool),
		AdvertisedAPs:    make(map[string]map[string]bool),
		ProtocolCounts:   make(map[string]int),
	}
}
