package storage

import (
	"database/sql"
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
		device_type TEXT,          -- <<< NEW COLUMN
		behavioral_clues TEXT, -- <<< NEW COLUMN
		FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
		UNIQUE(campaign_id, mac_address)
	);
	-- (Other table definitions are unchanged)
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
