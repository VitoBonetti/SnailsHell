package server

import (
	"fmt"
	"gonetmap/model"
	"gonetmap/storage"
)

// ComparisonResult holds the results of comparing two campaigns.
type ComparisonResult struct {
	BaseCampaign    *storage.CampaignInfo `json:"baseCampaign"`
	CompareCampaign *storage.CampaignInfo `json:"compareCampaign"`
	NewHosts        []*model.Host         `json:"newHosts"`
	MissingHosts    []*model.Host         `json:"missingHosts"`
	ChangedHosts    []HostChange          `json:"changedHosts"`
}

// HostChange details what has changed for a host between two scans.
type HostChange struct {
	Host         *model.Host           `json:"host"`
	Changes      []string              `json:"changes"`
	NewPorts     []model.Port          `json:"newPorts"`
	RemovedPorts []model.Port          `json:"removedPorts"`
	NewVulns     []model.Vulnerability `json:"newVulns"`
	RemovedVulns []model.Vulnerability `json:"removedVulns"`
}

// CompareCampaigns performs a diff between two campaigns.
func CompareCampaigns(baseCampaignID, compCampaignID int64) (*ComparisonResult, error) {
	baseCampaign, err := storage.GetCampaignByID(baseCampaignID)
	if err != nil {
		return nil, fmt.Errorf("could not get base campaign: %w", err)
	}
	compCampaign, err := storage.GetCampaignByID(compCampaignID)
	if err != nil {
		return nil, fmt.Errorf("could not get comparison campaign: %w", err)
	}

	baseHosts, err := storage.GetFullHostsForCampaign(baseCampaignID)
	if err != nil {
		return nil, fmt.Errorf("could not get hosts for base campaign: %w", err)
	}
	compHosts, err := storage.GetFullHostsForCampaign(compCampaignID)
	if err != nil {
		return nil, fmt.Errorf("could not get hosts for comparison campaign: %w", err)
	}

	result := &ComparisonResult{
		BaseCampaign:    baseCampaign,
		CompareCampaign: compCampaign,
		NewHosts:        []*model.Host{},
		MissingHosts:    []*model.Host{},
		ChangedHosts:    []HostChange{},
	}

	// Find new and changed hosts
	for mac, compHost := range compHosts {
		if baseHost, found := baseHosts[mac]; found {
			// Host exists in both, check for changes
			change := compareSingleHost(baseHost, compHost)
			if len(change.Changes) > 0 {
				result.ChangedHosts = append(result.ChangedHosts, change)
			}
		} else {
			// Host is new
			result.NewHosts = append(result.NewHosts, compHost)
		}
	}

	// Find missing hosts
	for mac, baseHost := range baseHosts {
		if _, found := compHosts[mac]; !found {
			result.MissingHosts = append(result.MissingHosts, baseHost)
		}
	}

	return result, nil
}

func compareSingleHost(base, comp *model.Host) HostChange {
	change := HostChange{Host: comp, Changes: []string{}}

	// Compare status
	if base.Status != comp.Status {
		change.Changes = append(change.Changes, fmt.Sprintf("Status changed from '%s' to '%s'", base.Status, comp.Status))
	}

	// Compare OS
	if base.Fingerprint.OperatingSystem != comp.Fingerprint.OperatingSystem {
		change.Changes = append(change.Changes, fmt.Sprintf("OS changed from '%s' to '%s'", base.Fingerprint.OperatingSystem, comp.Fingerprint.OperatingSystem))
	}

	// Compare Ports
	change.NewPorts, change.RemovedPorts = comparePorts(base.Ports, comp.Ports)
	if len(change.NewPorts) > 0 {
		change.Changes = append(change.Changes, fmt.Sprintf("Found %d new port(s)", len(change.NewPorts)))
	}
	if len(change.RemovedPorts) > 0 {
		change.Changes = append(change.Changes, fmt.Sprintf("Found %d removed port(s)", len(change.RemovedPorts)))
	}

	// Compare Vulnerabilities
	change.NewVulns, change.RemovedVulns = compareVulns(base.Findings, comp.Findings)
	if len(change.NewVulns) > 0 {
		change.Changes = append(change.Changes, fmt.Sprintf("Found %d new vulnerability/ies", len(change.NewVulns)))
	}
	if len(change.RemovedVulns) > 0 {
		change.Changes = append(change.Changes, fmt.Sprintf("Found %d removed vulnerability/ies", len(change.RemovedVulns)))
	}

	return change
}

func comparePorts(base, comp map[int]model.Port) (new, removed []model.Port) {
	for portID, compPort := range comp {
		if _, found := base[portID]; !found {
			new = append(new, compPort)
		}
	}
	for portID, basePort := range base {
		if _, found := comp[portID]; !found {
			removed = append(removed, basePort)
		}
	}
	return
}

func compareVulns(base, comp map[model.FindingCategory][]model.Vulnerability) (new, removed []model.Vulnerability) {
	baseVulns := make(map[string]model.Vulnerability)
	for _, cat := range base {
		for _, v := range cat {
			key := fmt.Sprintf("%d-%s", v.PortID, v.CVE)
			baseVulns[key] = v
		}
	}

	compVulns := make(map[string]model.Vulnerability)
	for _, cat := range comp {
		for _, v := range cat {
			key := fmt.Sprintf("%d-%s", v.PortID, v.CVE)
			compVulns[key] = v
		}
	}

	for key, compVuln := range compVulns {
		if _, found := baseVulns[key]; !found {
			new = append(new, compVuln)
		}
	}
	for key, baseVuln := range baseVulns {
		if _, found := compVulns[key]; !found {
			removed = append(removed, baseVuln)
		}
	}
	return
}
