package storage

import (
	"SnailsHell/model"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB(filepath string) error {
	var err error
	DB, err = sql.Open("sqlite", filepath)
	if err != nil {
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
	CREATE TABLE IF NOT EXISTS credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		campaign_id INTEGER NOT NULL,
		host_id INTEGER NOT NULL,
		endpoint TEXT,
		type TEXT,
		value TEXT,
		pcap_file TEXT,
		FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
		FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS web_responses (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_id INTEGER NOT NULL,
		port_id INTEGER NOT NULL,
		method TEXT NOT NULL,
		status_code INTEGER,
		headers TEXT,
		FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
		FOREIGN KEY(port_id) REFERENCES ports(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS screenshots (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_id INTEGER NOT NULL,
		port_id INTEGER NOT NULL,
		image_data BLOB,
		capture_time DATETIME,
		FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
		FOREIGN KEY(port_id) REFERENCES ports(id) ON DELETE CASCADE
	);
	`
	if _, err := DB.Exec(schema); err != nil {
		return fmt.Errorf("could not create database schema: %w", err)
	}
	fmt.Println("✅ Database schema initialized successfully.")
	return nil
}

// SaveScanResults intelligently saves or merges host data into the database.
func SaveScanResults(campaignID int64, networkMap *model.NetworkMap, summary *model.PcapSummary) error {
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("could not begin database transaction: %w", err)
	}
	defer tx.Rollback()

	// Prepare statements for reuse
	hostInsertStmt, _ := tx.Prepare(`INSERT INTO hosts(campaign_id, mac_address, ip_address, os_guess, vendor, status, discovered_by, device_type, behavioral_clues) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	defer hostInsertStmt.Close()
	hostUpdateStmt, _ := tx.Prepare(`UPDATE hosts SET ip_address=?, os_guess=?, vendor=?, status=?, device_type=?, behavioral_clues=?, mac_address=? WHERE id=?`)
	defer hostUpdateStmt.Close()
	portStmt, _ := tx.Prepare(`INSERT INTO ports(host_id, port_number, protocol, state, service, version) VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(host_id, port_number, protocol) DO UPDATE SET state=excluded.state, service=excluded.service, version=excluded.version;`)
	defer portStmt.Close()
	vulnStmt, _ := tx.Prepare(`INSERT INTO vulnerabilities(host_id, port_id, cve, description, state, category) VALUES(?, ?, ?, ?, ?, ?);`)
	defer vulnStmt.Close()
	commStmt, _ := tx.Prepare(`INSERT INTO communications(host_id, counterpart_ip, packet_count, geo_country, geo_city, geo_isp) VALUES(?, ?, ?, ?, ?, ?);`)
	defer commStmt.Close()
	dnsStmt, _ := tx.Prepare(`INSERT OR IGNORE INTO dns_lookups(host_id, domain) VALUES(?, ?);`)
	defer dnsStmt.Close()
	handshakeStmt, _ := tx.Prepare(`INSERT INTO handshakes(campaign_id, ap_mac, client_mac, ssid, state, pcap_file, hccapx_data) VALUES (?, ?, ?, ?, ?, ?, ?);`)
	defer handshakeStmt.Close()
	credentialStmt, _ := tx.Prepare(`INSERT INTO credentials(campaign_id, host_id, endpoint, type, value, pcap_file) VALUES (?, ?, ?, ?, ?, ?);`)
	defer credentialStmt.Close()
	webResponseStmt, _ := tx.Prepare(`INSERT INTO web_responses(host_id, port_id, method, status_code, headers) VALUES (?, ?, ?, ?, ?);`)
	defer webResponseStmt.Close()
	screenshotStmt, _ := tx.Prepare(`INSERT INTO screenshots(host_id, port_id, image_data, capture_time) VALUES (?, ?, ?, ?);`)
	defer screenshotStmt.Close()

	for _, host := range networkMap.Hosts {
		var hostID int64
		var mainIP, vendor, osGuess, deviceType, clues string

		// Extract primary IP and fingerprint data from the host model
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

		// --- Intelligent Host Merging Logic ---
		var existingHostID int64
		// 1. Try to find an existing host by its MAC address.
		err := tx.QueryRow("SELECT id FROM hosts WHERE campaign_id = ? AND mac_address = ?", campaignID, host.MACAddress).Scan(&existingHostID)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("could not query host by MAC %s: %w", host.MACAddress, err)
		}

		// 2. If not found by MAC, try to find by IP address.
		if existingHostID == 0 && mainIP != "" {
			err = tx.QueryRow("SELECT id FROM hosts WHERE campaign_id = ? AND ip_address = ?", campaignID, mainIP).Scan(&existingHostID)
			if err != nil && err != sql.ErrNoRows {
				return fmt.Errorf("could not query host by IP %s: %w", mainIP, err)
			}
		}

		if existingHostID != 0 {
			// **UPDATE/MERGE**: We found an existing host. Update it with new info.
			hostID = existingHostID
			_, err = hostUpdateStmt.Exec(mainIP, osGuess, vendor, host.Status, deviceType, clues, host.MACAddress, hostID)
			if err != nil {
				return fmt.Errorf("could not update host %d: %w", hostID, err)
			}
		} else {
			// **INSERT**: This is a new host. Insert it.
			res, err := hostInsertStmt.Exec(campaignID, host.MACAddress, mainIP, osGuess, vendor, host.Status, host.DiscoveredBy, deviceType, clues)
			if err != nil {
				return fmt.Errorf("could not insert host %s: %w", host.MACAddress, err)
			}
			hostID, _ = res.LastInsertId()
		}
		// --- End of Merging Logic ---
		host.ID = hostID

		portNumberToDBID := make(map[int]int64)
		for _, port := range host.Ports {
			res, err := portStmt.Exec(hostID, port.ID, port.Protocol, port.State, port.Service, port.Version)
			if err != nil {
				return fmt.Errorf("could not save port %d for host %d: %w", port.ID, hostID, err)
			}
			portDBID, err := res.LastInsertId()
			if err != nil { // This happens on conflict/update
				err = tx.QueryRow("SELECT id FROM ports WHERE host_id = ? AND port_number = ? AND protocol = ?", hostID, port.ID, port.Protocol).Scan(&portDBID)
				if err != nil {
					return fmt.Errorf("could not get existing port ID for port %d: %w", port.ID, err)
				}
			}
			portNumberToDBID[port.ID] = portDBID
		}

		for _, findingList := range host.Findings {
			for _, vuln := range findingList {
				var portDBID sql.NullInt64
				if vuln.PortID != 0 {
					if id, ok := portNumberToDBID[vuln.PortID]; ok {
						portDBID = sql.NullInt64{Int64: id, Valid: true}
					}
				}
				_, err := vulnStmt.Exec(hostID, portDBID, vuln.CVE, vuln.Description, vuln.State, vuln.Category)
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
		for _, webResponse := range host.WebResponses {
			portDBID, ok := portNumberToDBID[webResponse.PortID]
			if !ok {
				continue
			}
			headersJSON, _ := json.Marshal(webResponse.Headers)
			_, err := webResponseStmt.Exec(hostID, portDBID, webResponse.Method, webResponse.StatusCode, string(headersJSON))
			if err != nil {
				return fmt.Errorf("could not save web response for host %d: %w", hostID, err)
			}
		}
		for _, screenshot := range host.Screenshots {
			portDBID, ok := portNumberToDBID[screenshot.PortID]
			if !ok {
				continue
			}
			_, err := screenshotStmt.Exec(hostID, portDBID, screenshot.ImageData, screenshot.CaptureTime)
			if err != nil {
				return fmt.Errorf("could not save screenshot for host %d: %w", hostID, err)
			}
		}
	}

	for _, hs := range summary.CapturedHandshakes {
		_, err := handshakeStmt.Exec(campaignID, hs.APMAC, hs.ClientMAC, hs.SSID, hs.HandshakeState, hs.PcapFile, hs.HCCAPX)
		if err != nil {
			return fmt.Errorf("could not save handshake: %w", err)
		}
	}

	for _, cred := range summary.Credentials {
		var hostID int64
		err := tx.QueryRow("SELECT id FROM hosts WHERE campaign_id = ? AND mac_address = ?", campaignID, cred.HostMAC).Scan(&hostID)
		if err != nil {
			fmt.Printf("Warning: Could not find host with MAC %s for credential, skipping.\n", cred.HostMAC)
			continue
		}
		_, err = credentialStmt.Exec(campaignID, hostID, cred.Endpoint, cred.Type, cred.Value, cred.PcapFile)
		if err != nil {
			return fmt.Errorf("could not save credential: %w", err)
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
	ID           int64  `json:"id"`
	MACAddress   string `json:"mac_address"`
	IPAddress    string `json:"ip_address"`
	Vendor       string `json:"vendor"`
	Status       string `json:"status"`
	DiscoveredBy string `json:"discovered_by"`
	DeviceType   string `json:"device_type"`
	HasVulns     bool   `json:"has_vulns"`
}

// ReportHostInfo is a more detailed struct for report generation.
type ReportHostInfo struct {
	ID         int64
	MACAddress string
	IPAddress  string
	Vendor     string
	OSGuess    string
	DeviceType string
	Status     string
	HasVulns   bool
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

// GetHostByID retrieves all details for a single host, but only if it belongs to the specified campaign.
func GetHostByID(hostID int64, campaignID int64) (*model.Host, error) {
	host := model.NewHost("")
	host.ID = hostID
	var ipAddress, vendor, osGuess, deviceType, clues string

	err := DB.QueryRow(`
		SELECT mac_address, ip_address, vendor, os_guess, status, device_type, behavioral_clues
		FROM hosts WHERE id = ? AND campaign_id = ?`, hostID, campaignID).Scan(
		&host.MACAddress, &ipAddress, &vendor, &osGuess, &host.Status, &deviceType, &clues,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("host with ID %d not found in campaign %d", hostID, campaignID)
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

	webRows, err := DB.Query("SELECT p.port_number, wr.method, wr.status_code, wr.headers FROM web_responses wr JOIN ports p ON wr.port_id = p.id WHERE wr.host_id = ?", hostID)
	if err != nil {
		return nil, fmt.Errorf("could not query web responses for host %d: %w", hostID, err)
	}
	defer webRows.Close()
	for webRows.Next() {
		var wr model.WebResponse
		var headersJSON string
		if err := webRows.Scan(&wr.PortID, &wr.Method, &wr.StatusCode, &headersJSON); err != nil {
			return nil, fmt.Errorf("could not scan web response row for host %d: %w", hostID, err)
		}
		if err := json.Unmarshal([]byte(headersJSON), &wr.Headers); err != nil {
			return nil, fmt.Errorf("could not unmarshal web response headers for host %d: %w", hostID, err)
		}
		host.WebResponses = append(host.WebResponses, wr)
	}

	screenshotRows, err := DB.Query("SELECT s.id, p.port_number, s.image_data, s.capture_time FROM screenshots s JOIN ports p ON s.port_id = p.id WHERE s.host_id = ?", hostID)
	if err != nil {
		return nil, fmt.Errorf("could not query screenshots for host %d: %w", hostID, err)
	}
	defer screenshotRows.Close()
	for screenshotRows.Next() {
		var s model.Screenshot
		if err := screenshotRows.Scan(&s.ID, &s.PortID, &s.ImageData, &s.CaptureTime); err != nil {
			return nil, fmt.Errorf("could not scan screenshot row for host %d: %w", hostID, err)
		}
		host.Screenshots = append(host.Screenshots, s)
	}

	return host, nil
}

// ... (rest of the file is the same as the previous step)
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

func GetHostsByCampaignPaginated(campaignID int64, limit, offset int, search, filter string) ([]HostInfo, int, error) {
	var hosts []HostInfo
	var totalHosts int

	baseQuery := `
        FROM hosts h
        LEFT JOIN vulnerabilities v ON h.id = v.host_id
        WHERE h.campaign_id = ?
    `
	args := []interface{}{campaignID}

	var conditions []string
	if filter == "up" {
		conditions = append(conditions, "h.status = 'up'")
	} else if filter == "down" {
		conditions = append(conditions, "(h.status = 'down' OR h.status = '')")
	} else if filter == "vulns" {
		conditions = append(conditions, "v.id IS NOT NULL")
	}

	if search != "" {
		searchCondition := "(h.ip_address LIKE ? OR h.mac_address LIKE ? OR h.vendor LIKE ?)"
		conditions = append(conditions, searchCondition)
		searchTerm := "%" + search + "%"
		args = append(args, searchTerm, searchTerm, searchTerm)
	}

	if len(conditions) > 0 {
		baseQuery += " AND " + strings.Join(conditions, " AND ")
	}

	countQuery := "SELECT COUNT(DISTINCT h.id) " + baseQuery
	err := DB.QueryRow(countQuery, args...).Scan(&totalHosts)
	if err != nil {
		return nil, 0, fmt.Errorf("could not count filtered hosts: %w", err)
	}

	selectQuery := `
        SELECT DISTINCT h.id, h.mac_address, h.ip_address, h.vendor, h.status,
        (CASE WHEN EXISTS (SELECT 1 FROM vulnerabilities WHERE host_id = h.id) THEN 1 ELSE 0 END) as has_vulns
    ` + baseQuery + " ORDER BY h.ip_address DESC, h.id DESC LIMIT ? OFFSET ?"

	args = append(args, limit, offset)

	rows, err := DB.Query(selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("could not query paginated hosts: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var h HostInfo
		if err := rows.Scan(&h.ID, &h.MACAddress, &h.IPAddress, &h.Vendor, &h.Status, &h.HasVulns); err != nil {
			return nil, 0, fmt.Errorf("could not scan paginated host row: %w", err)
		}
		hosts = append(hosts, h)
	}

	return hosts, totalHosts, nil
}

func DeleteCampaignByID(id int64) error {
	_, err := DB.Exec("DELETE FROM campaigns WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("could not delete campaign with id %d: %w", id, err)
	}
	return nil
}

func GetAllHostsForReport(campaignID int64) ([]ReportHostInfo, error) {
	query := `
        SELECT
            h.id, h.mac_address, h.ip_address, h.vendor, h.os_guess, h.device_type, h.status,
            (CASE WHEN EXISTS (SELECT 1 FROM vulnerabilities WHERE host_id = h.id) THEN 1 ELSE 0 END) as has_vulns
        FROM hosts h
        WHERE h.campaign_id = ? ORDER BY h.ip_address`
	rows, err := DB.Query(query, campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not query all hosts for report: %w", err)
	}
	defer rows.Close()

	var hosts []ReportHostInfo
	for rows.Next() {
		var h ReportHostInfo
		if err := rows.Scan(&h.ID, &h.MACAddress, &h.IPAddress, &h.Vendor, &h.OSGuess, &h.DeviceType, &h.Status, &h.HasVulns); err != nil {
			return nil, fmt.Errorf("could not scan host row for report: %w", err)
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

func GetAllPortsForReport(campaignID int64) ([][]string, error) {
	query := `
        SELECT h.mac_address, p.port_number, p.protocol, p.state, p.service, p.version
        FROM ports p JOIN hosts h ON p.host_id = h.id
        WHERE h.campaign_id = ? ORDER BY h.mac_address, p.port_number`
	rows, err := DB.Query(query, campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not query ports for report: %w", err)
	}
	defer rows.Close()

	var results [][]string
	for rows.Next() {
		var mac, service, version string
		var port int
		var protocol, state string
		if err := rows.Scan(&mac, &port, &protocol, &state, &service, &version); err != nil {
			return nil, err
		}
		results = append(results, []string{mac, strconv.Itoa(port), protocol, state, service, version})
	}
	return results, nil
}

func GetAllVulnsForReport(campaignID int64) ([][]string, error) {
	query := `
        SELECT h.mac_address, v.cve, v.category, v.state, v.description
        FROM vulnerabilities v JOIN hosts h ON v.host_id = h.id
        WHERE h.campaign_id = ? ORDER BY h.mac_address, v.category`
	rows, err := DB.Query(query, campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not query vulnerabilities for report: %w", err)
	}
	defer rows.Close()

	var results [][]string
	for rows.Next() {
		var mac, cve, category, state, description string
		if err := rows.Scan(&mac, &cve, &category, &state, &description); err != nil {
			return nil, err
		}
		results = append(results, []string{mac, cve, category, state, description})
	}
	return results, nil
}

func GetAllCommsForReport(campaignID int64) ([][]string, error) {
	query := `
        SELECT h.mac_address, c.counterpart_ip, c.packet_count, c.geo_city, c.geo_country, c.geo_isp
        FROM communications c JOIN hosts h ON c.host_id = h.id
        WHERE h.campaign_id = ? ORDER BY h.mac_address, c.counterpart_ip`
	rows, err := DB.Query(query, campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not query communications for report: %w", err)
	}
	defer rows.Close()

	var results [][]string
	for rows.Next() {
		var mac, counterpart, city, country, isp string
		var packetCount int
		if err := rows.Scan(&mac, &counterpart, &packetCount, &city, &country, &isp); err != nil {
			return nil, err
		}
		results = append(results, []string{mac, counterpart, strconv.Itoa(packetCount), city, country, isp})
	}
	return results, nil
}

func GetAllDNSForReport(campaignID int64) ([][]string, error) {
	query := `
        SELECT h.mac_address, d.domain
        FROM dns_lookups d JOIN hosts h ON d.host_id = h.id
        WHERE h.campaign_id = ? ORDER BY h.mac_address, d.domain`
	rows, err := DB.Query(query, campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not query dns lookups for report: %w", err)
	}
	defer rows.Close()

	var results [][]string
	for rows.Next() {
		var mac, domain string
		if err := rows.Scan(&mac, &domain); err != nil {
			return nil, err
		}
		results = append(results, []string{mac, domain})
	}
	return results, nil
}

func GetHandshakesByCampaignPaginated(campaignID int64, limit, offset int) ([]model.ReportHandshakeInfo, error) {
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

	var handshakes []model.ReportHandshakeInfo
	for rows.Next() {
		var h model.ReportHandshakeInfo
		var hccapxData []byte
		if err := rows.Scan(&h.ID, &h.APMAC, &h.ClientMAC, &h.SSID, &h.PcapFile, &hccapxData); err != nil {
			return nil, fmt.Errorf("could not scan paginated handshake row: %w", err)
		}
		h.HCCAPX = hex.EncodeToString(hccapxData)
		handshakes = append(handshakes, h)
	}
	return handshakes, nil
}

func GetAllHandshakesForReport(campaignID int64) ([]model.ReportHandshakeInfo, error) {
	return GetHandshakesByCampaignPaginated(campaignID, 10000, 0)
}

func CountHandshakesByCampaign(campaignID int64) (int, error) {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM handshakes WHERE campaign_id = ?", campaignID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("could not count handshakes for campaign %d: %w", campaignID, err)
	}
	return count, err
}

func GetFullHostsForCampaign(campaignID int64) (map[string]*model.Host, error) {
	hosts := make(map[string]*model.Host)

	rows, err := DB.Query("SELECT id, mac_address, ip_address, vendor, os_guess, status, device_type FROM hosts WHERE campaign_id = ?", campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not query hosts for campaign %d: %w", campaignID, err)
	}
	defer rows.Close()

	hostIDtoMac := make(map[int64]string)
	for rows.Next() {
		h := model.NewHost("")
		var ipAddress, vendor, osGuess, deviceType string
		if err := rows.Scan(&h.ID, &h.MACAddress, &ipAddress, &vendor, &osGuess, &h.Status, &deviceType); err != nil {
			return nil, err
		}
		h.IPv4Addresses[ipAddress] = true
		h.Fingerprint.Vendor = vendor
		h.Fingerprint.OperatingSystem = osGuess
		h.Fingerprint.DeviceType = deviceType
		hosts[h.MACAddress] = h
		hostIDtoMac[h.ID] = h.MACAddress
	}

	portRows, err := DB.Query("SELECT host_id, port_number, protocol, state, service, version FROM ports p JOIN hosts h ON p.host_id = h.id WHERE h.campaign_id = ?", campaignID)
	if err != nil {
		return nil, err
	}
	defer portRows.Close()
	for portRows.Next() {
		var hostID int64
		var p model.Port
		if err := portRows.Scan(&hostID, &p.ID, &p.Protocol, &p.State, &p.Service, &p.Version); err != nil {
			return nil, err
		}
		if mac, ok := hostIDtoMac[hostID]; ok {
			hosts[mac].Ports[p.ID] = p
		}
	}

	vulnRows, err := DB.Query("SELECT host_id, port_id, cve, description, state, category FROM vulnerabilities v JOIN hosts h ON v.host_id = h.id WHERE h.campaign_id = ?", campaignID)
	if err != nil {
		return nil, err
	}
	defer vulnRows.Close()
	for vulnRows.Next() {
		var hostID, portDBID sql.NullInt64
		var v model.Vulnerability
		if err := vulnRows.Scan(&hostID, &portDBID, &v.CVE, &v.Description, &v.State, &v.Category); err != nil {
			return nil, err
		}
		if mac, ok := hostIDtoMac[hostID.Int64]; ok {
			hosts[mac].Findings[v.Category] = append(hosts[mac].Findings[v.Category], v)
		}
	}

	return hosts, nil
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
	CapturedCredentialsCount  int
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

	err = DB.QueryRow("SELECT COUNT(*) FROM credentials WHERE campaign_id = ?", campaignID).Scan(&summary.CapturedCredentialsCount)
	if err != nil {
		return nil, fmt.Errorf("could not count credentials for dashboard: %w", err)
	}

	return summary, nil
}

func GetCredentialsByCampaign(campaignID int64) ([]model.Credential, error) {
	rows, err := DB.Query(`
		SELECT c.id, c.endpoint, c.type, c.value, c.pcap_file, h.mac_address
		FROM credentials c
		JOIN hosts h ON c.host_id = h.id
		WHERE c.campaign_id = ?
		ORDER BY c.id DESC`, campaignID)
	if err != nil {
		return nil, fmt.Errorf("could not query credentials for campaign %d: %w", campaignID, err)
	}
	defer rows.Close()

	var credentials []model.Credential
	for rows.Next() {
		var c model.Credential
		if err := rows.Scan(&c.ID, &c.Endpoint, &c.Type, &c.Value, &c.PcapFile, &c.HostMAC); err != nil {
			return nil, fmt.Errorf("could not scan credential row: %w", err)
		}
		credentials = append(credentials, c)
	}
	return credentials, nil
}

func CountCredentialsByCampaign(campaignID int64) (int, error) {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM credentials WHERE campaign_id = ?", campaignID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("could not count credentials for campaign %d: %w", campaignID, err)
	}
	return count, err
}

// GetScreenshotByID retrieves the raw image data for a single screenshot.
func GetScreenshotByID(id int64) ([]byte, error) {
	var data []byte
	err := DB.QueryRow("SELECT image_data FROM screenshots WHERE id = ?", id).Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("screenshot with ID %d not found", id)
		}
		return nil, err
	}
	return data, nil
}
