package model

// Communication represents a single interaction between our host and another IP.
type Communication struct {
	CounterpartIP string
	PacketCount   int
	Protocols     map[string]int // Track different protocols used in the conversation
}

// NetworkMap is the top-level structure holding all network information.
type NetworkMap struct {
	// The map key is now the host's MAC address (if available) or its IP address.
	// This allows us to track a physical device even if its IP changes.
	Hosts map[string]*Host
}

// Host represents a single device on the network.
type Host struct {
	// A host can now have multiple IPs associated with it over time.
	IPv4Addresses  map[string]bool // Using a map as a set for quick lookups
	IPv6Address    string
	MACAddress     string
	Status         string
	Hostnames      []string
	Ports          map[int]Port // Map of PortID to Port to avoid duplicate ports
	Communications map[string]*Communication
	DiscoveredBy   string
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
