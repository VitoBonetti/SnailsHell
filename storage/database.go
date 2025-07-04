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
		// Wrap the original error with more context.
		return fmt.Errorf("could not open database file %s: %w", filepath, err)
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
		return fmt.Errorf("could not begin database transaction: %w", err)
	}
	defer tx.Rollback() // Rollback on error, Commit will override this if successful

	hostStmt, err := tx.Prepare(`
		INSERT INTO hosts(campaign_id, mac_address, ip_address, os_guess, vendor, status, discovered_by, device_type, behavioral_clues) 
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?) 
		ON CONFLICT(campaign_id, mac_address) DO UPDATE SET 
		ip_address=excluded.ip_address, os_guess=excluded.os_guess, vendor=excluded.vendor, status=excluded.status, device_type=excluded.device_type, behavioral_clues=excluded.behavioral_clues;
	`)
	if err != nil {
		return fmt.Errorf("could not prepare host statement: %w", err)
	}
	defer hostStmt.Close()

	portStmt, err := tx.Prepare(`INSERT INTO ports(host_id, port_number, protocol, state, service, version) VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(host_id, port_number, protocol) DO UPDATE SET state=excluded.state, service=excluded.service, version=excluded.version;`)
	if err != nil {
		return fmt.Errorf("could not prepare port statement: %w", err)
	}
	defer portStmt.Close()

	vulnStmt, err := tx.Prepare(`INSERT INTO vulnerabilities(host_id, port_id, cve, description, state, category) VALUES(?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return fmt.Errorf("could not prepare vulnerability statement: %w", err)
	}
	defer vulnStmt.Close()

	commStmt, err := tx.Prepare(`INSERT INTO communications(host_id, counterpart_ip, packet_count, geo_country, geo_city, geo_isp) VALUES(?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return fmt.Errorf("could not prepare communication statement: %w", err)
	}
	defer commStmt.Close()

	dnsStmt, err := tx.Prepare(`INSERT OR IGNORE INTO dns_lookups(host_id, domain) VALUES(?, ?);`)
	if err != nil {
		return fmt.Errorf("could not prepare dns lookup statement: %w", err)
	}
	defer dnsStmt.Close()

	handshakeStmt, err := tx.Prepare(`INSERT INTO handshakes(campaign_id, ap_mac, client_mac, ssid, state, pcap_file, hccapx_data) VALUES (?, ?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return fmt.Errorf("could not prepare handshake statement: %w", err)
	}
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
			// This branch is taken when the host already exists and we need to get its ID for foreign keys.
			err = tx.QueryRow("SELECT id FROM hosts WHERE campaign_id = ? AND mac_address = ?", campaignID, host.MACAddress).Scan(&hostID)
			if err != nil {
				return fmt.Errorf("could not get existing host ID for %s: %w", host.MACAddress, err)
			}
		}

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
				return 0, fmt.Errorf("could not prepare campaign insert statement: %w", err)
			}
			defer stmt.Close()
			res, err := stmt.Exec(name, time.Now())
			if err != nil {
				return 0, fmt.Errorf("could not create new campaign '%s': %w", name, err)
			}
			id, err := res.LastInsertId()
			if err != nil {
				return 0, fmt.Errorf("could not get ID of new campaign '%s': %w", name, err)
			}
			return id, nil
		} else {
			return 0, fmt.Errorf("could not query for campaign '%s': %w", name, err)
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
		return nil, fmt.Errorf("could not query hosts for campaign %d: %w", campaignID, err)
	}
	defer rows.Close()

	var hosts []HostInfo
	for rows.Next() {
		var h HostInfo
		if err := rows.Scan(&h.ID, &h.MACAddress, &h.IPAddress, &h.Vendor, &h.Status); err != nil {
			return nil, fmt.Errorf("could not scan host row: %w", err)
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
		return nil, fmt.Errorf("could not query campaigns: %w", err)
	}
	defer rows.Close()

	var campaigns []CampaignInfo
	for rows.Next() {
		var c CampaignInfo
		if err := rows.Scan(&c.ID, &c.Name, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("could not scan campaign row: %w", err)
		}
		campaigns = append(campaigns, c)
	}
	return campaigns, nil
}

// GetHostByID retrieves all details for a single host, correctly handling nested data.
func GetHostByID(hostID int64) (*model.Host, error) {
	host := &model.Host{
		Ports:          make(map[int]model.Port),
		IPv4Addresses:  make(map[string]bool),
		Fingerprint:    &model.Fingerprint{},
		Findings:       make(map[model.FindingCategory][]model.Vulnerability),
		Communications: make(map[string]*model.Communication),
		DNSLookups:     make(map[string]bool),
	}

	host.ID = hostID
	var ipAddress, vendor, osGuess, deviceType, clues string

	err := DB.QueryRow(`
		SELECT mac_address, ip_address, vendor, os_guess, status, device_type, behavioral_clues
		FROM hosts WHERE id = ?`, hostID).Scan(
		&host.MACAddress, &ipAddress, &vendor, &osGuess, &host.Status, &deviceType, &clues,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("host with ID %d not found", hostID)
		}
		return nil, fmt.Errorf("error querying host %d: %w", hostID, err)
	}

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

	portRows, err := DB.Query("SELECT id, port_number, protocol, state, service, version FROM ports WHERE host_id = ?", hostID)
	if err != nil {
		return nil, fmt.Errorf("could not query ports for host %d: %w", hostID, err)
	}
	defer portRows.Close()

	portIDMap := make(map[int64]int)
	for portRows.Next() {
		var p model.Port
		var dbPortID int64
		if err := portRows.Scan(&dbPortID, &p.ID, &p.Protocol, &p.State, &p.Service, &p.Version); err != nil {
			return nil, fmt.Errorf("could not scan port row for host %d: %w", hostID, err)
		}
		host.Ports[p.ID] = p
		portIDMap[dbPortID] = p.ID
	}

	vulnRows, err := DB.Query("SELECT port_id, cve, description, state, category FROM vulnerabilities WHERE host_id = ?", hostID)
	if err != nil {
		return nil, fmt.Errorf("could not query vulnerabilities for host %d: %w", hostID, err)
	}
	defer vulnRows.Close()
	for vulnRows.Next() {
		var v model.Vulnerability
		var portID sql.NullInt64
		if err := vulnRows.Scan(&portID, &v.CVE, &v.Description, &v.State, &v.Category); err != nil {
			return nil, fmt.Errorf("could not scan vulnerability row for host %d: %w", hostID, err)
		}
		if portID.Valid {
			v.PortID = portIDMap[portID.Int64]
		}
		host.Findings[v.Category] = append(host.Findings[v.Category], v)
	}

	commRows, err := DB.Query("SELECT counterpart_ip, packet_count, geo_country, geo_city, geo_isp FROM communications WHERE host_id = ?", hostID)
	if err != nil {
		return nil, fmt.Errorf("could not query communications for host %d: %w", hostID, err)
	}
	defer commRows.Close()
	for commRows.Next() {
		var comm model.Communication
		var country, city, isp sql.NullString
		if err := commRows.Scan(&comm.CounterpartIP, &comm.PacketCount, &country, &city, &isp); err != nil {
			return nil, fmt.Errorf("could not scan communication row for host %d: %w", hostID, err)
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

	dnsRows, err := DB.Query("SELECT domain FROM dns_lookups WHERE host_id = ?", hostID)
	if err != nil {
		return nil, fmt.Errorf("could not query dns lookups for host %d: %w", hostID, err)
	}
	defer dnsRows.Close()
	for dnsRows.Next() {
		var domain string
		if err := dnsRows.Scan(&domain); err != nil {
			return nil, fmt.Errorf("could not scan dns lookup row for host %d: %w", hostID, err)
		}
		host.DNSLookups[domain] = true
	}

	return host, nil
}

func GetCampaignByID(id int64) (*CampaignInfo, error) {
	var c CampaignInfo
	err := DB.QueryRow("SELECT id, name, created_at FROM campaigns WHERE id = ?", id).Scan(&c.ID, &c.Name, &c.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("campaign with ID %d not found", id)
		}
		return nil, fmt.Errorf("could not query campaign %d: %w", id, err)
	}
	return &c, nil
}

func GetHostsByCampaignPaginated(campaignID int64, limit, offset int) ([]HostInfo, error) {
	rows, err := DB.Query("SELECT id, mac_address, ip_address, vendor, status, discovered_by, device_type, behavioral_clues FROM hosts WHERE campaign_id = ? ORDER BY ip_address DESC LIMIT ? OFFSET ?", campaignID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("could not query paginated hosts for campaign %d: %w", campaignID, err)
	}
	defer rows.Close()

	var hosts []HostInfo
	for rows.Next() {
		var h HostInfo
		if err := rows.Scan(&h.ID, &h.MACAddress, &h.IPAddress, &h.Vendor, &h.Status, &h.DiscoveredBy, &h.DeviceType, &h.BehavioralClues); err != nil {
			return nil, fmt.Errorf("could not scan paginated host row: %w", err)
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

func CountHostsByCampaign(campaignID int64) (int, error) {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM hosts WHERE campaign_id = ?", campaignID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("could not count hosts for campaign %d: %w", campaignID, err)
	}
	return count, err
}

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

func GetDashboardSummary(campaignID int64) (*DashboardSummary, error) {
	summary := &DashboardSummary{}
	var err error

	err = DB.QueryRow("SELECT COUNT(*) FROM hosts WHERE campaign_id = ?", campaignID).Scan(&summary.TotalHosts)
	if err != nil {
		return nil, fmt.Errorf("could not count total hosts for dashboard: %w", err)
	}

	err = DB.QueryRow("SELECT COUNT(*) FROM hosts WHERE campaign_id = ? AND status = 'up'", campaignID).Scan(&summary.HostsUp)
	if err != nil {
		return nil, fmt.Errorf("could not count 'up' hosts for dashboard: %w", err)
	}
	summary.HostsDown = summary.TotalHosts - summary.HostsUp

	rows, err := DB.Query(`
		SELECT p.port_number
		FROM ports p
		JOIN hosts h ON p.host_id = h.id
		WHERE h.campaign_id = ? AND p.state = 'open'
		GROUP BY p.port_number
		ORDER BY COUNT(p.port_number) DESC
		LIMIT 5`, campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not get common ports for dashboard: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var port string
		if err := rows.Scan(&port); err != nil {
			return nil, fmt.Errorf("could not scan common port for dashboard: %w", err)
		}
		summary.MostCommonPorts = append(summary.MostCommonPorts, port)
	}

	err = DB.QueryRow("SELECT COUNT(*) FROM vulnerabilities v JOIN hosts h ON v.host_id = h.id WHERE h.campaign_id = ? AND v.category = ?", campaignID, model.CriticalFinding).Scan(&summary.CriticalVulnCount)
	if err != nil {
		return nil, fmt.Errorf("could not count critical vulnerabilities for dashboard: %w", err)
	}
	err = DB.QueryRow("SELECT COUNT(*) FROM vulnerabilities v JOIN hosts h ON v.host_id = h.id WHERE h.campaign_id = ? AND v.category = ?", campaignID, model.PotentialFinding).Scan(&summary.PotentialVulnCount)
	if err != nil {
		return nil, fmt.Errorf("could not count potential vulnerabilities for dashboard: %w", err)
	}
	err = DB.QueryRow("SELECT COUNT(*) FROM vulnerabilities v JOIN hosts h ON v.host_id = h.id WHERE h.campaign_id = ? AND v.category = ?", campaignID, model.InformationalFinding).Scan(&summary.InformationalVulnCount)
	if err != nil {
		return nil, fmt.Errorf("could not count informational vulnerabilities for dashboard: %w", err)
	}

	summary.TotalVulnerabilitiesCount = summary.CriticalVulnCount + summary.PotentialVulnCount + summary.InformationalVulnCount

	err = DB.QueryRow("SELECT COUNT(*) FROM handshakes WHERE campaign_id = ?", campaignID).Scan(&summary.CapturedHandshakesCount)
	if err != nil {
		return nil, fmt.Errorf("could not count handshakes for dashboard: %w", err)
	}

	return summary, nil
}

type HandshakeInfo struct {
	ID        int64
	APMAC     string
	ClientMAC string
	SSID      string
	PcapFile  string
	HCCAPX    string
}

func CountHandshakesByCampaign(campaignID int64) (int, error) {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM handshakes WHERE campaign_id = ?", campaignID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("could not count handshakes for campaign %d: %w", campaignID, err)
	}
	return count, err
}

func GetHandshakesByCampaignPaginated(campaignID int64, limit, offset int) ([]HandshakeInfo, error) {
	rows, err := DB.Query(`
		SELECT id, ap_mac, client_mac, ssid, pcap_file, hccapx_data
		FROM handshakes
		WHERE campaign_id = ?
		ORDER BY id DESC
		LIMIT ? OFFSET ?`, campaignID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("could not query paginated handshakes for campaign %d: %w", campaignID, err)
	}
	defer rows.Close()

	var handshakes []HandshakeInfo
	for rows.Next() {
		var h HandshakeInfo
		var hccapxData []byte
		if err := rows.Scan(&h.ID, &h.APMAC, &h.ClientMAC, &h.SSID, &h.PcapFile, &hccapxData); err != nil {
			return nil, fmt.Errorf("could not scan paginated handshake row: %w", err)
		}
		h.HCCAPX = hex.EncodeToString(hccapxData)
		handshakes = append(handshakes, h)
	}
	return handshakes, nil
}
