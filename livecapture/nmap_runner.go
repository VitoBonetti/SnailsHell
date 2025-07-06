package livecapture

import (
	"SnailsHell/config"
	"SnailsHell/model"
	"SnailsHell/processing"
	"SnailsHell/storage"
	"SnailsHell/webenum"
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var nmapPath string

// InitNmap finds the nmap executable and verifies it's ready for use.
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

// IsNmapFound returns true if the nmap executable path is known.
func IsNmapFound() bool {
	return nmapPath != ""
}

// printProgressBar draws a simple text-based progress bar.
func printProgressBar(percent int) {
	const width = 50
	bar := strings.Repeat("=", (percent*width)/100)
	spaces := strings.Repeat(" ", width-len(bar))
	fmt.Printf("\r[%s%s] %d%% Complete", bar, spaces, percent)
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
	args = append(args, "--stats-every", "5s", "-v")
	args = append(args, "-oX", tmpFileName)
	args = append(args, target)

	log.Printf("Executing nmap command: %s %v", nmapPath, args)
	cmd := exec.CommandContext(ctx, nmapPath, args...)

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start nmap command: %w", err)
	}

	re := regexp.MustCompile(`\s(\d+\.\d+)% done`)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		merged := io.MultiReader(stdout, stderr)
		scanner := bufio.NewScanner(merged)
		for scanner.Scan() {
			line := scanner.Text()
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				progress, _ := strconv.ParseFloat(matches[1], 64)
				printProgressBar(int(progress))
			}
		}
	}()

	err = cmd.Wait()
	wg.Wait()
	fmt.Println()

	if err != nil {
		return nil, fmt.Errorf("nmap command failed: %w", err)
	}

	log.Println("Nmap scan completed successfully. Processing results from file...")

	networkMap := model.NewNetworkMap()
	if err := processing.MergeFromFile(tmpFileName, networkMap); err != nil {
		return nil, fmt.Errorf("failed to process nmap XML output from file %s: %w", tmpFileName, err)
	}

	// Probe web servers found by Nmap
	log.Println("Probing discovered web servers...")
	for _, host := range networkMap.Hosts {
		webenum.ProbeWebServer(host)
		webenum.TakeScreenshot(host)
	}

	summary := model.NewPcapSummary()
	if err := storage.SaveScanResults(campaignID, networkMap, summary); err != nil {
		return nil, fmt.Errorf("failed to save nmap scan results: %w", err)
	}

	log.Printf("✅ Nmap scan results for target '%s' saved to campaign '%s'.", target, campaignName)
	return networkMap, nil
}
