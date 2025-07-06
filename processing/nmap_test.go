package processing

import (
	"SnailsHell/model"
	"os"
	"testing"
)

// TestMergeFromFile tests the parsing of an Nmap XML file.
func TestMergeFromFile(t *testing.T) {
	// A sample Nmap XML output string for our test.
	xmlData := `
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O -oX test.xml 192.168.1.1" start="1672531200" version="7.91">
<host>
<status state="up" reason="arp-response"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Test-Inc"/>
<ports>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.18.0"/>
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack"/>
<service name="https" product="nginx" version="1.18.0"/>
<script id="ssl-cert" output="Subject: commonName=test.local"/>
</port>
</ports>
<os>
<osmatch name="Linux 4.15 - 5.6" accuracy="100">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.x"/>
</osmatch>
</os>
</host>
</nmaprun>
`
	// Create a temporary file to write our test XML data to.
	tmpfile, err := os.CreateTemp("", "test_nmap_*.xml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name()) // Ensure the file is cleaned up after the test.

	if _, err := tmpfile.Write([]byte(xmlData)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	// --- Run the function we want to test ---
	networkMap := model.NewNetworkMap()
	err = MergeFromFile(tmpfile.Name(), networkMap)
	if err != nil {
		t.Fatalf("MergeFromFile failed: %v", err)
	}

	// --- Assertions ---
	// Check that the data was parsed correctly.

	if len(networkMap.Hosts) != 1 {
		t.Fatalf("Expected 1 host, but got %d", len(networkMap.Hosts))
	}

	mac := "00:11:22:33:44:55"
	host, ok := networkMap.Hosts[mac]
	if !ok {
		t.Fatalf("Host with MAC %s not found in network map", mac)
	}

	if host.Status != "up" {
		t.Errorf("Host status incorrect, got: %s, want: %s", host.Status, "up")
	}

	if !host.IPv4Addresses["192.168.1.1"] {
		t.Error("Expected IP address 192.168.1.1 to be present")
	}

	if host.Fingerprint.Vendor != "Test-Inc" {
		t.Errorf("Vendor incorrect, got: %s, want: %s", host.Fingerprint.Vendor, "Test-Inc")
	}

	if host.Fingerprint.OperatingSystem != "Linux 4.15 - 5.6" {
		t.Errorf("OS incorrect, got: %s, want: %s", host.Fingerprint.OperatingSystem, "Linux 4.15 - 5.6")
	}

	if len(host.Ports) != 2 {
		t.Fatalf("Expected 2 ports, but got %d", len(host.Ports))
	}

	port80, ok := host.Ports[80]
	if !ok {
		t.Fatal("Port 80 not found")
	}
	if port80.Service != "http" {
		t.Errorf("Port 80 service incorrect, got: %s, want: http", port80.Service)
	}

	if len(host.Findings) == 0 {
		t.Fatal("Expected findings from NSE script, but got none")
	}

	infoFindings := host.Findings[model.InformationalFinding]
	if len(infoFindings) != 1 {
		t.Fatalf("Expected 1 informational finding, but got %d", len(infoFindings))
	}
	if infoFindings[0].CVE != "ssl-cert" {
		t.Errorf("Finding CVE incorrect, got: %s, want: ssl-cert", infoFindings[0].CVE)
	}
}
