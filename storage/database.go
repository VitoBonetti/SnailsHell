package storage

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"gonetmap/model"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB(filepath string) error {
	var err error
	DB, err = sql.Open("sqlite", filepath)
	if err != nil {
		return fmt.Errorf("could not open database: %w", err)
	}
	if err = DB.Ping(); err != nil {
		return fmt.Errorf("could not connect to database: %w", err)
	}
	_, err = DB.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		return fmt.Errorf("could not enable foreign keys: %w", err)
	}
	return createTables()
}

func createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS campaigns (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		created_at DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS hosts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		campaign_id INTEGER NOT NULL,
		mac_address TEXT NOT NULL,
		ip_address TEXT,
		os_guess TEXT,
		vendor TEXT,
		status TEXT,
		discovered_by TEXT,
		device_type TEXT,          
		behavioral_clues TEXT, 
		FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
		UNIQUE(campaign_id, mac_address)
	);
	
	CREATE TABLE IF NOT EXISTS ports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_id INTEGER NOT NULL,
		port_number INTEGER NOT NULL,
		protocol TEXT NOT NULL,
		state TEXT,
		service TEXT,
		version TEXT,
		FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
		UNIQUE(host_id, port_number, protocol)
	);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_id INTEGER NOT NULL,
		port_id INTEGER,
		cve TEXT,
		description TEXT,
		state TEXT,
		category TEXT,
		FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
		FOREIGN KEY(port_id) REFERENCES ports(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS communications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_id INTEGER NOT NULL,
		counterpart_ip TEXT NOT NULL,
		packet_count INTEGER,
		geo_country TEXT,
		geo_city TEXT,
		geo_isp TEXT,
		FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS dns_lookups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_id INTEGER NOT NULL,
		domain TEXT NOT NULL,
		FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
		UNIQUE(host_id, domain)
	);
	CREATE TABLE IF NOT EXISTS handshakes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		campaign_id INTEGER NOT NULL,
		ap_mac TEXT NOT NULL,
		client_mac TEXT NOT NULL,
		ssid TEXT,
		state TEXT,
		pcap_file TEXT,
		hccapx_data BLOB,
		FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
	);
	`
	if _, err := DB.Exec(schema); err != nil {
		return fmt.Errorf("could not create database schema: %w", err)
	}
	fmt.Println("✅ Database schema initialized successfully.")
	return nil
}

// SaveScanResults now saves all host data correctly.
func SaveScanResults(campaignID int64, networkMap *model.NetworkMap, summary *model.PcapSummary) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	hostStmt, _ := tx.Prepare(`
		INSERT INTO hosts(campaign_id, mac_address, ip_address, os_guess, vendor, status, discovered_by, device_type, behavioral_clues) 
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?) 
		ON CONFLICT(campaign_id, mac_address) DO UPDATE SET 
		ip_address=excluded.ip_address, os_guess=excluded.os_guess, vendor=excluded.vendor, status=excluded.status, device_type=excluded.device_type, behavioral_clues=excluded.behavioral_clues;
	`)
	// (other prepared statements are unchanged)
	portStmt, _ := tx.Prepare(`INSERT INTO ports(host_id, port_number, protocol, state, service, version) VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(host_id, port_number, protocol) DO UPDATE SET state=excluded.state, service=excluded.service, version=excluded.version;`)
	vulnStmt, _ := tx.Prepare(`INSERT INTO vulnerabilities(host_id, port_id, cve, description, state, category) VALUES(?, ?, ?, ?, ?, ?);`)
	commStmt, _ := tx.Prepare(`INSERT INTO communications(host_id, counterpart_ip, packet_count, geo_country, geo_city, geo_isp) VALUES(?, ?, ?, ?, ?, ?);`)
	dnsStmt, _ := tx.Prepare(`INSERT OR IGNORE INTO dns_lookups(host_id, domain) VALUES(?, ?);`)
	handshakeStmt, _ := tx.Prepare(`INSERT INTO handshakes(campaign_id, ap_mac, client_mac, ssid, state, pcap_file, hccapx_data) VALUES (?, ?, ?, ?, ?, ?, ?);`)

	defer hostStmt.Close()
	defer portStmt.Close()
	defer vulnStmt.Close()
	defer commStmt.Close()
	defer dnsStmt.Close()
	defer handshakeStmt.Close()

	for _, host := range networkMap.Hosts {
		var mainIP, vendor, osGuess, deviceType, clues string
		if len(host.IPv4Addresses) > 0 {
			for ip := range host.IPv4Addresses {
				mainIP = ip
				break
			}
		}
		if host.Fingerprint != nil {
			vendor = host.Fingerprint.Vendor
			osGuess = host.Fingerprint.OperatingSystem
			deviceType = host.Fingerprint.DeviceType

			// Convert the clues map to a single string
			var clueList []string
			for clue := range host.Fingerprint.BehavioralClues {
				clueList = append(clueList, clue)
			}
			clues = strings.Join(clueList, ", ")
		}

		res, err := hostStmt.Exec(campaignID, host.MACAddress, mainIP, osGuess, vendor, host.Status, host.DiscoveredBy, deviceType, clues)
		if err != nil {
			return fmt.Errorf("could not save host %s: %w", host.MACAddress, err)
		}

		hostID, err := res.LastInsertId()
		if err != nil {
			err = tx.QueryRow("SELECT id FROM hosts WHERE campaign_id = ? AND mac_address = ?", campaignID, host.MACAddress).Scan(&hostID)
			if err != nil {
				return fmt.Errorf("could not get host ID for %s: %w", host.MACAddress, err)
			}
		}

		// (rest of the save logic is unchanged)
		for _, port := range host.Ports {
			_, err := portStmt.Exec(hostID, port.ID, port.Protocol, port.State, port.Service, port.Version)
			if err != nil {
				return fmt.Errorf("could not save port %d for host %d: %w", port.ID, hostID, err)
			}
		}
		for _, findingList := range host.Findings {
			for _, vuln := range findingList {
				_, err := vulnStmt.Exec(hostID, nil, vuln.CVE, vuln.Description, vuln.State, vuln.Category)
				if err != nil {
					return fmt.Errorf("could not save vulnerability for host %d: %w", hostID, err)
				}
			}
		}
		for _, comm := range host.Communications {
			var country, city, isp string
			if comm.Geo != nil {
				country, city, isp = comm.Geo.Country, comm.Geo.City, comm.Geo.ISP
			}
			_, err := commStmt.Exec(hostID, comm.CounterpartIP, comm.PacketCount, country, city, isp)
			if err != nil {
				return fmt.Errorf("could not save communication for host %d: %w", hostID, err)
			}
		}
		for domain := range host.DNSLookups {
			_, err := dnsStmt.Exec(hostID, domain)
			if err != nil {
				return fmt.Errorf("could not save DNS lookup for host %d: %w", hostID, err)
			}
		}
	}
	for _, hs := range summary.CapturedHandshakes {
		_, err := handshakeStmt.Exec(campaignID, hs.APMAC, hs.ClientMAC, hs.SSID, hs.HandshakeState, hs.PcapFile, hs.HCCAPX)
		if err != nil {
			return fmt.Errorf("could not save handshake: %w", err)
		}
	}

	return tx.Commit()
}

func GetOrCreateCampaign(name string) (int64, error) {
	var campaignID int64
	err := DB.QueryRow("SELECT id FROM campaigns WHERE name = ?", name).Scan(&campaignID)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("Campaign '%s' not found. Creating a new one.\n", name)
			stmt, err := DB.Prepare("INSERT INTO campaigns(name, created_at) VALUES(?, ?)")
			if err != nil {
				return 0, err
			}
			defer stmt.Close()
			res, err := stmt.Exec(name, time.Now())
			if err != nil {
				return 0, err
			}
			id, err := res.LastInsertId()
			if err != nil {
				return 0, err
			}
			return id, nil
		} else {
			return 0, err
		}
	}
	fmt.Printf("Found existing campaign '%s'. New data will be added to it.\n", name)
	return campaignID, nil
}

// HostInfo is a simplified struct for display in the UI.
type HostInfo struct {
	ID              int64  `json:"id"`
	MACAddress      string `json:"mac_address"`
	IPAddress       string `json:"ip_address"`
	Vendor          string `json:"vendor"`
	Status          string `json:"status"`
	DiscoveredBy    string `json:"discovered_by"`
	DeviceType      string `json:"device_type"`
	BehavioralClues string `json:"behavioral_clues"`
}

// GetHostsByCampaign retrieves a list of all hosts for a given campaign.
func GetHostsByCampaign(campaignID int64) ([]HostInfo, error) {
	rows, err := DB.Query("SELECT id, mac_address, ip_address, vendor, status FROM hosts WHERE campaign_id = ?", campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []HostInfo
	for rows.Next() {
		var h HostInfo
		if err := rows.Scan(&h.ID, &h.MACAddress, &h.IPAddress, &h.Vendor, &h.Status); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// CampaignInfo is a simple struct for listing campaigns.
type CampaignInfo struct {
	ID        int64
	Name      string
	CreatedAt time.Time
}

// ListCampaigns retrieves all campaigns from the database.
func ListCampaigns() ([]CampaignInfo, error) {
	rows, err := DB.Query("SELECT id, name, created_at FROM campaigns ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var campaigns []CampaignInfo
	for rows.Next() {
		var c CampaignInfo
		if err := rows.Scan(&c.ID, &c.Name, &c.CreatedAt); err != nil {
			return nil, err
		}
		campaigns = append(campaigns, c)
	}
	return campaigns, nil
}

// GetHostByID retrieves all details for a single host, correctly handling nested data.
func GetHostByID(hostID int64) (*model.Host, error) {
	// Initialize the host with its nested maps and structs
	host := &model.Host{
		Ports:          make(map[int]model.Port),
		IPv4Addresses:  make(map[string]bool),
		Fingerprint:    &model.Fingerprint{},
		Findings:       make(map[model.FindingCategory][]model.Vulnerability), // Initialize Findings
		Communications: make(map[string]*model.Communication),                 // Initialize Communications
		DNSLookups:     make(map[string]bool),                                 // Initialize DNSLookups
	}

	host.ID = hostID

	// Temporary variables to hold the data scanned from the database
	var ipAddress, vendor, osGuess, deviceType, clues string

	// Get main host details from the database
	err := DB.QueryRow(`
		SELECT mac_address, ip_address, vendor, os_guess, status, device_type, behavioral_clues
		FROM hosts WHERE id = ?`, hostID).Scan(
		&host.MACAddress, &ipAddress, &vendor, &osGuess, &host.Status, &deviceType, &clues,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("host with ID %d not found", hostID)
		}
		return nil, fmt.Errorf("error querying host: %w", err)
	}

	// Correctly populate the nested structs
	host.IPv4Addresses[ipAddress] = true
	host.Fingerprint.Vendor = vendor
	host.Fingerprint.OperatingSystem = osGuess
	host.Fingerprint.DeviceType = deviceType

	host.Fingerprint.BehavioralClues = make(map[string]bool)
	if clues != "" {
		for _, clue := range strings.Split(clues, ", ") {
			host.Fingerprint.BehavioralClues[clue] = true
		}
	}

	// Get all ports for this host
	portRows, err := DB.Query("SELECT id, port_number, protocol, state, service, version FROM ports WHERE host_id = ?", hostID)
	if err != nil {
		return nil, err
	}
	defer portRows.Close()

	portIDMap := make(map[int64]int) // Map DB port ID to port number for vulnerabilities
	for portRows.Next() {
		var p model.Port
		var dbPortID int64
		if err := portRows.Scan(&dbPortID, &p.ID, &p.Protocol, &p.State, &p.Service, &p.Version); err != nil {
			return nil, err
		}
		host.Ports[p.ID] = p
		portIDMap[dbPortID] = p.ID
	}

	// NEW: Get vulnerabilities for this host
	vulnRows, err := DB.Query("SELECT port_id, cve, description, state, category FROM vulnerabilities WHERE host_id = ?", hostID)
	if err != nil {
		return nil, fmt.Errorf("could not query vulnerabilities: %w", err)
	}
	defer vulnRows.Close()
	for vulnRows.Next() {
		var v model.Vulnerability
		var portID sql.NullInt64
		if err := vulnRows.Scan(&portID, &v.CVE, &v.Description, &v.State, &v.Category); err != nil {
			return nil, err
		}
		if portID.Valid {
			v.PortID = portIDMap[portID.Int64]
		}
		host.Findings[v.Category] = append(host.Findings[v.Category], v)
	}

	// NEW: Get communications for this host
	commRows, err := DB.Query("SELECT counterpart_ip, packet_count, geo_country, geo_city, geo_isp FROM communications WHERE host_id = ?", hostID)
	if err != nil {
		return nil, fmt.Errorf("could not query communications: %w", err)
	}
	defer commRows.Close()
	for commRows.Next() {
		var comm model.Communication
		var country, city, isp sql.NullString
		if err := commRows.Scan(&comm.CounterpartIP, &comm.PacketCount, &country, &city, &isp); err != nil {
			return nil, err
		}
		if country.Valid || city.Valid || isp.Valid {
			comm.Geo = &model.GeoInfo{
				Country: country.String,
				City:    city.String,
				ISP:     isp.String,
			}
		}
		host.Communications[comm.CounterpartIP] = &comm
	}

	// NEW: Get DNS lookups for this host
	dnsRows, err := DB.Query("SELECT domain FROM dns_lookups WHERE host_id = ?", hostID)
	if err != nil {
		return nil, fmt.Errorf("could not query dns lookups: %w", err)
	}
	defer dnsRows.Close()
	for dnsRows.Next() {
		var domain string
		if err := dnsRows.Scan(&domain); err != nil {
			return nil, err
		}
		host.DNSLookups[domain] = true
	}

	return host, nil
}

func GetCampaignByID(id int64) (*CampaignInfo, error) {
	var c CampaignInfo
	err := DB.QueryRow("SELECT id, name, created_at FROM campaigns WHERE id = ?", id).Scan(&c.ID, &c.Name, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// GetHostsByCampaignPaginated retrieves a specific "page" of hosts.
func GetHostsByCampaignPaginated(campaignID int64, limit, offset int) ([]HostInfo, error) {
	rows, err := DB.Query("SELECT id, mac_address, ip_address, vendor, status, discovered_by, device_type, behavioral_clues FROM hosts WHERE campaign_id = ? ORDER BY ip_address DESC LIMIT ? OFFSET ?", campaignID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []HostInfo
	for rows.Next() {
		var h HostInfo
		if err := rows.Scan(&h.ID, &h.MACAddress, &h.IPAddress, &h.Vendor, &h.Status, &h.DiscoveredBy, &h.DeviceType, &h.BehavioralClues); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// CountHostsByCampaign returns the total number of hosts for a campaign.
func CountHostsByCampaign(campaignID int64) (int, error) {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM hosts WHERE campaign_id = ?", campaignID).Scan(&count)
	return count, err
}

// DashboardSummary holds summary data for the main dashboard.
type DashboardSummary struct {
	TotalHosts                int
	HostsUp                   int
	HostsDown                 int
	MostCommonPorts           []string
	CriticalVulnCount         int
	PotentialVulnCount        int
	InformationalVulnCount    int
	CapturedHandshakesCount   int
	TotalVulnerabilitiesCount int
}

// GetDashboardSummary retrieves summary statistics for a given campaign.
func GetDashboardSummary(campaignID int64) (*DashboardSummary, error) {
	summary := &DashboardSummary{}

	// Get total hosts
	err := DB.QueryRow("SELECT COUNT(*) FROM hosts WHERE campaign_id = ?", campaignID).Scan(&summary.TotalHosts)
	if err != nil {
		return nil, fmt.Errorf("could not count hosts: %w", err)
	}

	// Get hosts up/down
	err = DB.QueryRow("SELECT COUNT(*) FROM hosts WHERE campaign_id = ? AND status = 'up'", campaignID).Scan(&summary.HostsUp)
	if err != nil {
		return nil, fmt.Errorf("could not count up hosts: %w", err)
	}
	summary.HostsDown = summary.TotalHosts - summary.HostsUp

	// Get most common ports
	rows, err := DB.Query(`
		SELECT p.port_number
		FROM ports p
		JOIN hosts h ON p.host_id = h.id
		WHERE h.campaign_id = ? AND p.state = 'open'
		GROUP BY p.port_number
		ORDER BY COUNT(p.port_number) DESC
		LIMIT 5`, campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not get common ports: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var port string
		if err := rows.Scan(&port); err != nil {
			return nil, err
		}
		summary.MostCommonPorts = append(summary.MostCommonPorts, port)
	}

	// Get vulnerability counts
	err = DB.QueryRow("SELECT COUNT(*) FROM vulnerabilities v JOIN hosts h ON v.host_id = h.id WHERE h.campaign_id = ? AND v.category = ?", campaignID, model.CriticalFinding).Scan(&summary.CriticalVulnCount)
	if err != nil {
		return nil, fmt.Errorf("could not count critical vulnerabilities: %w", err)
	}
	err = DB.QueryRow("SELECT COUNT(*) FROM vulnerabilities v JOIN hosts h ON v.host_id = h.id WHERE h.campaign_id = ? AND v.category = ?", campaignID, model.PotentialFinding).Scan(&summary.PotentialVulnCount)
	if err != nil {
		return nil, fmt.Errorf("could not count potential vulnerabilities: %w", err)
	}
	err = DB.QueryRow("SELECT COUNT(*) FROM vulnerabilities v JOIN hosts h ON v.host_id = h.id WHERE h.campaign_id = ? AND v.category = ?", campaignID, model.InformationalFinding).Scan(&summary.InformationalVulnCount)
	if err != nil {
		return nil, fmt.Errorf("could not count informational vulnerabilities: %w", err)
	}

	summary.TotalVulnerabilitiesCount = summary.CriticalVulnCount + summary.PotentialVulnCount + summary.InformationalVulnCount

	err = DB.QueryRow("SELECT COUNT(*) FROM handshakes WHERE campaign_id = ?", campaignID).Scan(&summary.CapturedHandshakesCount)
	if err != nil {
		return nil, fmt.Errorf("could not count handshakes: %w", err)
	}

	return summary, nil
}

// NEW: HandshakeInfo is a struct for displaying handshakes in the UI.
type HandshakeInfo struct {
	ID        int64
	APMAC     string
	ClientMAC string
	SSID      string
	PcapFile  string
	HCCAPX    string // The hex-encoded data for display
}

// NEW: CountHandshakesByCampaign returns the total number of handshakes for a campaign.
func CountHandshakesByCampaign(campaignID int64) (int, error) {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM handshakes WHERE campaign_id = ?", campaignID).Scan(&count)
	return count, err
}

// RENAMED & UPDATED: This function is now paginated.
func GetHandshakesByCampaignPaginated(campaignID int64, limit, offset int) ([]HandshakeInfo, error) {
	rows, err := DB.Query(`
		SELECT id, ap_mac, client_mac, ssid, pcap_file, hccapx_data
		FROM handshakes
		WHERE campaign_id = ?
		ORDER BY id DESC
		LIMIT ? OFFSET ?`, campaignID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var handshakes []HandshakeInfo
	for rows.Next() {
		var h HandshakeInfo
		var hccapxData []byte
		if err := rows.Scan(&h.ID, &h.APMAC, &h.ClientMAC, &h.SSID, &h.PcapFile, &hccapxData); err != nil {
			return nil, err
		}
		h.HCCAPX = hex.EncodeToString(hccapxData)
		handshakes = append(handshakes, h)
	}
	return handshakes, nil
}
