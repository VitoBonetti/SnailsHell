package model

// Fingerprint holds clues about the device's identity.
type Fingerprint struct {
	Vendor          string // From the MAC address (e.g., "Apple, Inc.")
	OperatingSystem string // From Nmap's OS detection (e.g., "Windows 10")
	DeviceType      string // From Nmap's OS detection (e.g., "general purpose", "media device")
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
	// Add the new Fingerprint struct to our Host
	Fingerprint *Fingerprint
}

// Port represents a network port on a host.
type Port struct {
	ID       int
	Protocol string
	State    string
	Service  string
	Version  string
}

func NewNetworkMap() *NetworkMap {
	return &NetworkMap{
		Hosts: make(map[string]*Host),
	}
}
