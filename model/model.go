package model

// Communication represents a single interaction between our host and another IP.
type Communication struct {
	CounterpartIP   string
	PacketCount     int
	Protocol        string
	CounterpartPort int // We can add more details like this later
}

// NetworkMap is the top-level structure holding all network information.
type NetworkMap struct {
	// We'll change this to a map for faster lookups while enriching.
	// The key will be the host's IPv4 address.
	Hosts map[string]*Host
}

// Host represents a single device on the network.
type Host struct {
	IPv4Address    string
	IPv6Address    string
	MACAddress     string
	Status         string
	Hostnames      []string
	Ports          []Port
	Communications map[string]*Communication // Map to store conversations with other IPs
	DiscoveredBy   string                    // e.g., "Nmap", "Pcap", "Both"
}

// Port represents a network port on a host.
type Port struct {
	ID       int
	Protocol string
	State    string
	Service  string
	Version  string
}

// Helper function to create a new Host
func NewHost(ip string) *Host {
	return &Host{
		IPv4Address:    ip,
		Communications: make(map[string]*Communication),
		DiscoveredBy:   "Pcap", // Default to Pcap if created this way
	}
}
