package nmap

import (
	"encoding/xml"
	"fmt"
	"gonetmap/model"
	"io/ioutil"
	"strings"
)

// --- NEW: Add structs for OS Detection ---
type Os struct {
	OsMatches []OsMatch `xml:"osmatch"`
}
type OsMatch struct {
	Name      string    `xml:"name,attr"`
	Accuracy  string    `xml:"accuracy,attr"`
	OsClasses []OsClass `xml:"osclass"`
}
type OsClass struct {
	Type     string `xml:"type,attr"`
	Vendor   string `xml:"vendor,attr"`
	OsFamily string `xml:"osfamily,attr"`
	OsGen    string `xml:"osgen,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// (Existing XML parsing structs)
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}
type Host struct {
	Status    Status     `xml:"status"`
	Addresses []Address  `xml:"address"`
	Hostnames []Hostname `xml:"hostnames>hostname"`
	Ports     []Port     `xml:"ports>port"`
	// Add the Os struct to our Host parser
	Os Os `xml:"os"`
}
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	// Nmap provides the vendor for MAC addresses
	Vendor string `xml:"vendor,attr"`
}

// (Other structs remain unchanged)
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

// MergeFromFile now extracts OS and Vendor data.
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
		var currentIP, currentMAC, vendor string
		for _, addr := range nmapHost.Addresses {
			if addr.AddrType == "ipv4" {
				currentIP = addr.Addr
			} else if addr.AddrType == "mac" {
				currentMAC = strings.ToUpper(addr.Addr)
				// Capture the vendor if Nmap provides it
				if addr.Vendor != "" {
					vendor = addr.Vendor
				}
			}
		}

		key := currentMAC
		if key == "" {
			key = currentIP
		}
		if key == "" {
			continue
		}

		existingHost, found := networkMap.Hosts[key]
		if !found {
			existingHost = &model.Host{
				MACAddress:     currentMAC,
				IPv4Addresses:  make(map[string]bool),
				Ports:          make(map[int]model.Port),
				Communications: make(map[string]*model.Communication),
				Fingerprint:    &model.Fingerprint{}, // Initialize the fingerprint struct
				DiscoveredBy:   "Nmap",
			}
			networkMap.Hosts[key] = existingHost
		}

		if existingHost.Fingerprint == nil {
			existingHost.Fingerprint = &model.Fingerprint{}
		}

		// Update Fingerprint with Vendor
		if vendor != "" {
			existingHost.Fingerprint.Vendor = vendor
		}

		// --- NEW: Update Fingerprint with OS Details ---
		// We'll take the first, most accurate OS match from Nmap
		if len(nmapHost.Os.OsMatches) > 0 {
			bestMatch := nmapHost.Os.OsMatches[0]
			existingHost.Fingerprint.OperatingSystem = bestMatch.Name

			if len(bestMatch.OsClasses) > 0 {
				existingHost.Fingerprint.DeviceType = bestMatch.OsClasses[0].Type
			}
		}

		if currentIP != "" {
			existingHost.IPv4Addresses[currentIP] = true
		}
		existingHost.Status = nmapHost.Status.State

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
