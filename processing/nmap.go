package processing

import (
	"encoding/xml"
	"fmt"
	"gonetmap/model"
	"io"
	"os"
	"strings"
)

// NmapRun represents the top-level structure of an Nmap XML output.
type NmapRun struct {
	Hosts []NmapHost `xml:"host"`
}

// NmapHost represents a single host in the Nmap output.
type NmapHost struct {
	Status    NmapStatus     `xml:"status"`
	Addresses []NmapAddress  `xml:"address"`
	Hostnames []NmapHostname `xml:"hostnames>hostname"`
	Ports     []NmapPort     `xml:"ports>port"`
	OS        NmapOS         `xml:"os"`
}

// NmapStatus holds the state of a host (e.g., "up").
type NmapStatus struct {
	State string `xml:"state,attr"`
}

// NmapAddress holds an address (MAC or IP) for a host.
type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

// NmapHostname holds a hostname for a host.
type NmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// NmapPort represents a port scanned on a host.
type NmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    NmapState    `xml:"state"`
	Service  NmapService  `xml:"service"`
	Scripts  []NmapScript `xml:"script"`
}

// NmapState holds the state of a port (e.g., "open").
type NmapState struct {
	State string `xml:"state,attr"`
}

// NmapService holds information about the service running on a port.
type NmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// NmapOS holds operating system detection results.
type NmapOS struct {
	OSMatches []OSMatch `xml:"osmatch"`
}

// OSMatch represents a single OS guess from Nmap.
type OSMatch struct {
	Name      string    `xml:"name,attr"`
	Accuracy  string    `xml:"accuracy,attr"`
	OSClasses []OSClass `xml:"osclass"`
}

// OSClass provides more detail about the OS guess.
type OSClass struct {
	Type     string `xml:"type,attr"`
	Vendor   string `xml:"vendor,attr"`
	OSFamily string `xml:"osfamily,attr"`
	OSGen    string `xml:"osgen,attr"`
}

// NmapScript holds the output of an NSE script.
type NmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// MergeFromFile parses an Nmap XML file and merges its data into the NetworkMap.
func MergeFromFile(filename string, networkMap *model.NetworkMap) error {
	xmlFile, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open nmap file %s: %w", filename, err)
	}
	defer xmlFile.Close()

	byteValue, err := io.ReadAll(xmlFile)
	if err != nil {
		return fmt.Errorf("could not read nmap file %s: %w", filename, err)
	}

	return MergeFromXML(byteValue, networkMap)
}

// MergeFromXML parses Nmap XML data from a byte slice and merges it into the NetworkMap.
func MergeFromXML(byteValue []byte, networkMap *model.NetworkMap) error {
	var nmapRun NmapRun
	if err := xml.Unmarshal(byteValue, &nmapRun); err != nil {
		return fmt.Errorf("could not unmarshal nmap xml: %w", err)
	}

	for _, nmapHost := range nmapRun.Hosts {
		var mac, ip, vendor string
		for _, addr := range nmapHost.Addresses {
			if addr.AddrType == "mac" {
				mac = strings.ToUpper(addr.Addr)
				vendor = addr.Vendor
			} else if addr.AddrType == "ipv4" {
				ip = addr.Addr
			}
		}

		if mac == "" {
			continue // Skip hosts without a MAC address
		}

		host, found := networkMap.Hosts[mac]
		if !found {
			host = model.NewHost(mac)
			networkMap.Hosts[mac] = host
		}

		host.DiscoveredBy = "Nmap"
		host.Status = nmapHost.Status.State
		if ip != "" {
			host.IPv4Addresses[ip] = true
		}

		if host.Fingerprint.Vendor == "" {
			host.Fingerprint.Vendor = vendor
		}

		if len(nmapHost.OS.OSMatches) > 0 {
			bestMatch := nmapHost.OS.OSMatches[0]
			host.Fingerprint.OperatingSystem = bestMatch.Name
			if len(bestMatch.OSClasses) > 0 {
				host.Fingerprint.DeviceType = bestMatch.OSClasses[0].Type
			}
		}

		for _, nmapPort := range nmapHost.Ports {
			port := model.Port{
				ID:       nmapPort.PortID,
				Protocol: nmapPort.Protocol,
				State:    nmapPort.State.State,
				Service:  nmapPort.Service.Name,
				Version:  nmapPort.Service.Product + " " + nmapPort.Service.Version,
			}
			host.Ports[port.ID] = port

			for _, script := range nmapPort.Scripts {
				vuln := model.Vulnerability{
					CVE:         script.ID,
					Description: script.Output,
					PortID:      port.ID,
					Category:    model.InformationalFinding, // Default category
				}
				if strings.Contains(script.ID, "vuln") {
					vuln.Category = model.PotentialFinding
				}
				host.Findings[vuln.Category] = append(host.Findings[vuln.Category], vuln)
			}
		}
	}
	return nil
}
