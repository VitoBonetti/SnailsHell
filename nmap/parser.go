package nmap

import (
	"encoding/xml"
	"fmt"
	"gonetmap/model"
	"io/ioutil"
	"strings"
)

// (All XML parsing structs remain unchanged)
type Script struct {
	ID     string  `xml:"id,attr"`
	Output string  `xml:"output,attr"`
	Tables []Table `xml:"table"`
}
type Table struct {
	Elements []Elem `xml:"elem"`
}
type Elem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

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
}
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}
type Host struct {
	Status      Status     `xml:"status"`
	Addresses   []Address  `xml:"address"`
	Hostnames   []Hostname `xml:"hostnames>hostname"`
	Ports       []Port     `xml:"ports>port"`
	Os          Os         `xml:"os"`
	HostScripts []Script   `xml:"hostscript>script"`
}
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}
type Hostname struct {
	Name string `xml:"name,attr"`
}
type Port struct {
	Protocol string   `xml:"protocol,attr"`
	PortID   int      `xml:"portid,attr"`
	State    State    `xml:"state"`
	Service  Service  `xml:"service"`
	Scripts  []Script `xml:"script"`
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
			}
			if addr.AddrType == "mac" {
				currentMAC = strings.ToUpper(addr.Addr)
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
				MACAddress: currentMAC, IPv4Addresses: make(map[string]bool), Ports: make(map[int]model.Port),
				Communications: make(map[string]*model.Communication), DiscoveredBy: "Nmap",
				Findings:   make(map[model.FindingCategory][]model.Vulnerability),
				DNSLookups: make(map[string]bool),
			}
			networkMap.Hosts[key] = existingHost
		}
		if existingHost.Fingerprint == nil {
			existingHost.Fingerprint = &model.Fingerprint{BehavioralClues: make(map[string]bool)}
		}
		if vendor != "" {
			existingHost.Fingerprint.Vendor = vendor
		}
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
				existingHost.Ports[nmapPort.PortID] = model.Port{ID: nmapPort.PortID, Protocol: nmapPort.Protocol, State: nmapPort.State.State, Service: nmapPort.Service.Name, Version: nmapPort.Service.Product + " " + nmapPort.Service.Version}
			}
		}

		allScripts := nmapHost.HostScripts
		for _, p := range nmapHost.Ports {
			// Associate the port number with the script for context before parsing
			for i := range p.Scripts {
				p.Scripts[i].ID = fmt.Sprintf("%s|%d", p.Scripts[i].ID, p.PortID)
			}
			allScripts = append(allScripts, p.Scripts...)
		}
		for _, script := range allScripts {
			if vuln, category, isFinding := parseVulnerabilityFromScript(script); isFinding {
				existingHost.Findings[category] = append(existingHost.Findings[category], vuln)
			}
		}
	}
	return nil
}

// --- THIS FUNCTION IS NOW MUCH SMARTER! ---
func parseVulnerabilityFromScript(script Script) (model.Vulnerability, model.FindingCategory, bool) {
	// --- THE FIX IS HERE: More robust filtering and categorization ---

	// Separate the port from the script ID if it exists
	scriptIDParts := strings.Split(script.ID, "|")
	scriptID := scriptIDParts[0]

	// 1. Blocklist of scripts that are always informational and noisy
	informationalScripts := map[string]bool{
		"fingerprint-strings": true, "http-enum": true, "http-trane-info": true,
	}
	if informationalScripts[scriptID] {
		return model.Vulnerability{}, "", false
	}

	output := strings.TrimSpace(script.Output)

	// 2. Blocklist of negative or unhelpful phrases
	negativeFindings := []string{
		"Couldn't find any", "The SMTP server is not Exim", "false", "TIMEOUT", "ERROR:",
	}
	for _, finding := range negativeFindings {
		if strings.Contains(output, finding) {
			return model.Vulnerability{}, "", false
		}
	}
	if output == "" {
		return model.Vulnerability{}, "", false
	}

	// 3. Categorize based on content and script ID
	var category model.FindingCategory
	if scriptID == "vulners" || strings.Contains(output, "VULNERABLE:") {
		category = model.CriticalFinding
	} else if strings.Contains(scriptID, "vuln") {
		category = model.PotentialFinding
	} else {
		// If it's not a known type, we'll discard it to reduce noise
		return model.Vulnerability{}, "", false
	}

	vuln := model.Vulnerability{
		Description: output,
		Category:    category,
	}

	for _, table := range script.Tables {
		for _, elem := range table.Elements {
			if elem.Key == "id" {
				vuln.CVE = elem.Value
			}
			if elem.Key == "state" {
				vuln.State = strings.ToUpper(strings.TrimSpace(elem.Value))
			}
		}
	}

	if vuln.CVE == "" {
		vuln.CVE = scriptID
	}

	return vuln, category, true
}
