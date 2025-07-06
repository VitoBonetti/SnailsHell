package livecapture

import (
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

func InitNmap(cfg *config.Config) error {
	var err error
	if cfg.Nmap.Path != "" {
		if _, err := os.Stat(cfg.Nmap.Path); err == nil {
			nmapPath = cfg.Nmap.Path
		} else {
			return fmt.Errorf("nmap path specified in config.yaml not found: %s", cfg.Nmap.Path)
		}
	} else {
		nmapPath, err = exec.LookPath("nmap")
		if err != nil {
			return fmt.Errorf("nmap executable not found in system PATH. Please install nmap or specify its location in config.yaml")
		}
	}
	fmt.Printf("✅ Nmap executable found at: %s\n", nmapPath)
	return nil
}

func IsNmapFound() bool {
	return nmapPath != ""
}

// RunNmapScan executes an nmap scan and returns the processed network map.
func RunNmapScan(ctx context.Context, target, campaignName string) (*model.NetworkMap, error) {
	if !IsNmapFound() {
		return nil, fmt.Errorf("cannot run scan, nmap executable not found")
	}

	campaignID, err := storage.GetOrCreateCampaign(campaignName)
	if err != nil {
		return nil, fmt.Errorf("could not get or create campaign '%s': %w", campaignName, err)
	}

	tmpFile, err := os.CreateTemp("", "gonetmap-nmap-*.xml")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file for nmap output: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFileName := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temporary file handle: %w", err)
	}

	args := config.Cfg.Nmap.DefaultArgs
	args = append(args, "-oX", tmpFileName)
	args = append(args, target)

	log.Printf("Executing nmap command: %s %v", nmapPath, args)
	cmd := exec.CommandContext(ctx, nmapPath, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Nmap output:\n%s", string(output))
		return nil, fmt.Errorf("nmap command failed: %w", err)
	}

	log.Println("Nmap scan completed successfully. Processing results from file...")

	networkMap := model.NewNetworkMap()
	if err := processing.MergeFromFile(tmpFileName, networkMap); err != nil {
		log.Printf("Nmap output for debugging:\n%s", string(output))
		return nil, fmt.Errorf("failed to process nmap XML output from file %s: %w", tmpFileName, err)
	}

	summary := model.NewPcapSummary()
	if err := storage.SaveScanResults(campaignID, networkMap, summary); err != nil {
		return nil, fmt.Errorf("failed to save nmap scan results: %w", err)
	}

	log.Printf("✅ Nmap scan results for target '%s' saved to campaign '%s'.", target, campaignName)
	return networkMap, nil
}
