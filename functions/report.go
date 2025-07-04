package functions

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"fmt"
	"gonetmap/storage"
	"strconv"
)

// GenerateReportZip creates a ZIP archive in memory containing multiple CSV files.
func GenerateReportZip(campaignID int64) ([]byte, error) {
	// Create a buffer to write our archive to.
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// --- 1. Generate hosts.csv ---
	hosts, err := storage.GetAllHostsForReport(campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not get hosts for report: %w", err)
	}
	var hostData [][]string
	for _, h := range hosts {
		hostData = append(hostData, []string{
			strconv.FormatInt(h.ID, 10), h.IPAddress, h.MACAddress, h.Vendor,
			h.OSGuess, h.DeviceType, h.Status, strconv.FormatBool(h.HasVulns),
		})
	}
	err = createCSVInZip(zipWriter, "hosts.csv",
		[]string{"Host ID", "IP Address", "MAC Address", "Vendor", "OS Guess", "Device Type", "Status", "Has Vulnerabilities"},
		hostData)
	if err != nil {
		return nil, err
	}

	// --- 2. Generate ports.csv ---
	ports, err := storage.GetAllPortsForReport(campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not get ports for report: %w", err)
	}
	err = createCSVInZip(zipWriter, "ports.csv",
		[]string{"Host MAC", "Port", "Protocol", "State", "Service", "Version"},
		ports)
	if err != nil {
		return nil, err
	}

	// --- 3. Generate vulnerabilities.csv ---
	vulns, err := storage.GetAllVulnsForReport(campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not get vulnerabilities for report: %w", err)
	}
	err = createCSVInZip(zipWriter, "vulnerabilities.csv",
		[]string{"Host MAC", "CVE", "Category", "State", "Description"},
		vulns)
	if err != nil {
		return nil, err
	}

	// --- 4. Generate communications.csv ---
	comms, err := storage.GetAllCommsForReport(campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not get communications for report: %w", err)
	}
	err = createCSVInZip(zipWriter, "communications.csv",
		[]string{"Host MAC", "Counterpart IP", "Packet Count", "City", "Country", "ISP"},
		comms)
	if err != nil {
		return nil, err
	}

	// --- 5. Generate dns_lookups.csv ---
	dns, err := storage.GetAllDNSForReport(campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not get dns lookups for report: %w", err)
	}
	err = createCSVInZip(zipWriter, "dns_lookups.csv",
		[]string{"Host MAC", "Domain"},
		dns)
	if err != nil {
		return nil, err
	}

	// --- 6. Generate handshakes.csv ---
	handshakes, err := storage.GetAllHandshakesForReport(campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not get handshakes for report: %w", err)
	}
	var handshakeData [][]string
	for _, h := range handshakes {
		handshakeData = append(handshakeData, []string{
			h.SSID, h.APMAC, h.ClientMAC, h.PcapFile, h.HCCAPX,
		})
	}
	err = createCSVInZip(zipWriter, "handshakes.csv",
		[]string{"SSID", "AP MAC", "Client MAC", "Pcap File", "HCCAPX Hex"},
		handshakeData)
	if err != nil {
		return nil, err
	}

	// Close the zip writer to finalize the archive.
	if err := zipWriter.Close(); err != nil {
		return nil, fmt.Errorf("could not close zip writer: %w", err)
	}

	return buf.Bytes(), nil
}

// createCSVInZip is a helper function to write a CSV file into a zip archive.
func createCSVInZip(zipWriter *zip.Writer, filename string, header []string, data [][]string) error {
	// Create a new file in the zip archive.
	fileWriter, err := zipWriter.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create %s in zip: %w", filename, err)
	}

	// Create a CSV writer.
	csvWriter := csv.NewWriter(fileWriter)

	// Write the header.
	if err := csvWriter.Write(header); err != nil {
		return fmt.Errorf("failed to write header to %s: %w", filename, err)
	}

	// Write all the data rows.
	if err := csvWriter.WriteAll(data); err != nil {
		return fmt.Errorf("failed to write data to %s: %w", filename, err)
	}

	// Flush the writer to ensure everything is written.
	csvWriter.Flush()
	return csvWriter.Error()
}
