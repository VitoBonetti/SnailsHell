package livecapture

import (
	"bytes"
	"context"
	"fmt"
	"gonetmap/config"
	"gonetmap/model"
	"gonetmap/processing"
	"gonetmap/storage"
	"log"
	"os"
	"os/exec"
)

var nmapPath string

// InitNmap finds the nmap executable and verifies it's ready for use.
func InitNmap(cfg *config.Config) error {
	var err error
	if cfg.Nmap.Path != "" {
		// If path is specified, check if it exists
		if _, err := os.Stat(cfg.Nmap.Path); err == nil {
			nmapPath = cfg.Nmap.Path
		} else {
			return fmt.Errorf("nmap path specified in config.yaml not found: %s", cfg.Nmap.Path)
		}
	} else {
		// Otherwise, search the system PATH
		nmapPath, err = exec.LookPath("nmap")
		if err != nil {
			return fmt.Errorf("nmap executable not found in system PATH. Please install nmap or specify its location in config.yaml")
		}
	}
	fmt.Printf("✅ Nmap executable found at: %s\n", nmapPath)
	return nil
}

// IsNmapFound returns true if the nmap executable path is known.
func IsNmapFound() bool {
	return nmapPath != ""
}

// RunNmapScan executes an nmap scan for the given target and saves the results to the specified campaign.
func RunNmapScan(ctx context.Context, target, campaignName string) error {
	if !IsNmapFound() {
		return fmt.Errorf("cannot run scan, nmap executable not found")
	}

	campaignID, err := storage.GetOrCreateCampaign(campaignName)
	if err != nil {
		return fmt.Errorf("could not get or create campaign '%s': %w", campaignName, err)
	}

	// Basic nmap command: OS detection, Service versioning, output to XML.
	// We use '-oX -' to pipe the XML output directly to stdout.
	args := []string{"-O", "-sV", "-oX", "-", target}

	log.Printf("Executing nmap command: %s %v", nmapPath, args)
	cmd := exec.CommandContext(ctx, nmapPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Printf("Nmap stderr: %s", stderr.String())
		return fmt.Errorf("nmap command failed: %w", err)
	}

	log.Println("Nmap scan completed successfully. Processing results...")

	networkMap := model.NewNetworkMap()
	if err := processing.MergeFromXML(stdout.Bytes(), networkMap); err != nil {
		return fmt.Errorf("failed to process nmap XML output: %w", err)
	}

	// No pcap summary for a pure nmap scan
	summary := model.NewPcapSummary()

	if err := storage.SaveScanResults(campaignID, networkMap, summary); err != nil {
		return fmt.Errorf("failed to save nmap scan results: %w", err)
	}

	log.Printf("✅ Nmap scan results for target '%s' saved to campaign '%s'.", target, campaignName)
	return nil
}
