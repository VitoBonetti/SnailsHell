package nmap

import (
	"encoding/xml"
	"gonetmap/model" // Using lowercase module name
	"io/ioutil"
)

// Structs for parsing Nmap XML (no changes here)
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}
type Host struct {
	Status    Status     `xml:"status"`
	Addresses []Address  `xml:"address"`
	Hostnames []Hostname `xml:"hostnames>hostname"`
	Ports     []Port     `xml:"ports>port"`
}
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}
type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}
type Port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   int     `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}
type State struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}
type Service struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}
type Status struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// ParseFromFile now correctly creates and populates the map.
func ParseFromFile(filename string) (*model.NetworkMap, error) {
	xmlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var nmapRun NmapRun
	if err := xml.Unmarshal(xmlFile, &nmapRun); err != nil {
		return nil, err
	}

	networkMap := &model.NetworkMap{
		Hosts: make(map[string]*model.Host),
	}

	for _, nmapHost := range nmapRun.Hosts {
		host := model.Host{
			Status: nmapHost.Status.State,
		}

		for _, addr := range nmapHost.Addresses {
			switch addr.AddrType {
			case "ipv4":
				host.IPv4Address = addr.Addr
			case "ipv6":
				host.IPv6Address = addr.Addr
			case "mac":
				host.MACAddress = addr.Addr
			}
		}

		for _, h := range nmapHost.Hostnames {
			host.Hostnames = append(host.Hostnames, h.Name)
		}

		// --- THE FIX IS HERE ---
		// The loop now correctly ranges over nmapHost.Ports, not nmapRun.Ports.
		for _, nmapPort := range nmapHost.Ports {
			port := model.Port{
				ID:       nmapPort.PortID,
				Protocol: nmapPort.Protocol,
				State:    nmapPort.State.State,
				Service:  nmapPort.Service.Name,
				Version:  nmapPort.Service.Product + " " + nmapPort.Service.Version,
			}
			host.Ports = append(host.Ports, port)
		}

		if host.IPv4Address != "" {
			networkMap.Hosts[host.IPv4Address] = &host
		}
	}

	return networkMap, nil
}
