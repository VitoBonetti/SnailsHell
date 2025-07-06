package server

import (
	"SnailsHell/storage"
	"archive/zip"
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
)

// GenerateReportZip creates a ZIP archive in memory containing multiple CSV files.
func GenerateReportZip(campaignID int64) ([]byte, error) {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

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

	if err := zipWriter.Close(); err != nil {
		return nil, fmt.Errorf("could not close zip writer: %w", err)
	}

	return buf.Bytes(), nil
}

func createCSVInZip(zipWriter *zip.Writer, filename string, header []string, data [][]string) error {
	fileWriter, err := zipWriter.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create %s in zip: %w", filename, err)
	}
	csvWriter := csv.NewWriter(fileWriter)
	if err := csvWriter.Write(header); err != nil {
		return fmt.Errorf("failed to write header to %s: %w", filename, err)
	}
	if err := csvWriter.WriteAll(data); err != nil {
		return fmt.Errorf("failed to write data to %s: %w", filename, err)
	}
	csvWriter.Flush()
	return csvWriter.Error()
}
