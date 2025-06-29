package nmap

import (
	"encoding/xml"
	"fmt"
	"gonetmap/model"
	"io/ioutil"
	"strings"
)

// (XML parsing structs remain unchanged)
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
}
type Hostname struct {
	Name string `xml:"name,attr"`
}
type Port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   int     `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}
type State struct {
	State string `xml:"state,attr"`
}
type Service struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}
type Status struct {
	State string `xml:"state,attr"`
}

// MergeFromFile now merges data from an Nmap file into an existing NetworkMap.
func MergeFromFile(filename string, networkMap *model.NetworkMap) error {
	xmlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	var nmapRun NmapRun
	if err := xml.Unmarshal(xmlFile, &nmapRun); err != nil {
		return err
	}

	fmt.Printf("  -> Merging data from %s...\n", filename)

	for _, nmapHost := range nmapRun.Hosts {
		// Extract key info first to find the host
		var currentIP, currentMAC string
		for _, addr := range nmapHost.Addresses {
			if addr.AddrType == "ipv4" {
				currentIP = addr.Addr
			} else if addr.AddrType == "mac" {
				currentMAC = strings.ToUpper(addr.Addr)
			}
		}

		// Determine the unique key: prefer MAC address, fall back to IP.
		key := currentMAC
		if key == "" {
			key = currentIP
		}
		if key == "" {
			continue // Skip hosts with no identifiable address
		}

		// --- MERGE LOGIC ---
		// Check if we already have this host in our map
		existingHost, found := networkMap.Hosts[key]
		if !found {
			// If not found, create a new host entry
			existingHost = &model.Host{
				MACAddress:     currentMAC,
				IPv4Addresses:  make(map[string]bool),
				Ports:          make(map[int]model.Port),
				Communications: make(map[string]*model.Communication),
				DiscoveredBy:   "Nmap",
			}
			networkMap.Hosts[key] = existingHost
		}

		// Update or add the IP address
		if currentIP != "" {
			existingHost.IPv4Addresses[currentIP] = true
		}
		existingHost.Status = nmapHost.Status.State

		// Merge ports (only adds new or updates existing ones)
		for _, nmapPort := range nmapHost.Ports {
			if _, portExists := existingHost.Ports[nmapPort.PortID]; !portExists {
				existingHost.Ports[nmapPort.PortID] = model.Port{
					ID:       nmapPort.PortID,
					Protocol: nmapPort.Protocol,
					State:    nmapPort.State.State,
					Service:  nmapPort.Service.Name,
					Version:  nmapPort.Service.Product + " " + nmapPort.Service.Version,
				}
			}
		}
	}
	return nil
}
