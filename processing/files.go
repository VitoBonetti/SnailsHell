package processing

import (
	"SnailsHell/model"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// ProcessFiles handles the core logic of parsing Nmap and Pcap files concurrently.
func ProcessFiles(xmlFiles, pcapFiles []string) (*model.NetworkMap, *model.PcapSummary) {
	masterMap := model.NewNetworkMap()
	var mapMutex sync.Mutex

	var wg sync.WaitGroup
	errChan := make(chan error, len(xmlFiles)+len(pcapFiles))

	var processedCount int32
	totalFiles := int32(len(xmlFiles) + len(pcapFiles))
	done := make(chan bool)

	go func() {
		for {
			select {
			case <-done:
				return
			default:
				fmt.Printf("\rProcessing files: %d/%d", atomic.LoadInt32(&processedCount), totalFiles)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	if len(xmlFiles) > 0 {
		fmt.Println("\n--- Parsing Nmap files ---")
		for _, file := range xmlFiles {
			wg.Add(1)
			go func(filePath string) {
				defer wg.Done()
				defer atomic.AddInt32(&processedCount, 1)

				tempMap := model.NewNetworkMap()
				if err := MergeFromFile(filePath, tempMap); err != nil {
					errChan <- fmt.Errorf("could not parse Nmap file %s: %w", filePath, err)
					return
				}

				mapMutex.Lock()
				for k, v := range tempMap.Hosts {
					masterMap.Hosts[k] = v
				}
				mapMutex.Unlock()
			}(file)
		}
		wg.Wait()
	}

	globalSummary := model.NewPcapSummary()
	var pcapMutex sync.Mutex

	if len(pcapFiles) > 0 {
		fmt.Println("\n--- Enriching with Pcap files ---")
		for _, file := range pcapFiles {
			wg.Add(1)
			go func(filePath string) {
				defer wg.Done()
				defer atomic.AddInt32(&processedCount, 1)

				pcapMutex.Lock()
				defer pcapMutex.Unlock()

				if err := EnrichData(filePath, masterMap, globalSummary); err != nil {
					errChan <- fmt.Errorf("could not process pcap file %s: %w", filePath, err)
					return
				}
			}(file)
		}
		wg.Wait()
	}

	done <- true
	fmt.Printf("\rProcessing files: %d/%d... Done.\n", atomic.LoadInt32(&processedCount), totalFiles)

	close(errChan)
	hasErrors := false
	for err := range errChan {
		if !hasErrors {
			fmt.Println("\n--- Warnings ---")
			hasErrors = true
		}
		log.Printf("  - %v", err)
	}
	if hasErrors {
		fmt.Println("NOTE: Some files could not be processed completely. See warnings above.")
	}

	fmt.Printf("\n✅ File processing complete. Found %d unique hosts.\n\n", len(masterMap.Hosts))

	return masterMap, globalSummary
}

// EnrichData opens a pcap file and processes its packets.
func EnrichData(file string, networkMap *model.NetworkMap, summary *model.PcapSummary) error {
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		return fmt.Errorf("could not open pcap file %s: %w", file, err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ProcessPacket(packet, networkMap, summary, file)
	}
	return nil
}
