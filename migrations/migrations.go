package migrations

// Migration defines a single database schema migration.
type Migration struct {
	Version int
	Script  string
}

// allMigrations holds all the schema update scripts, ordered by version.
var allMigrations = []Migration{
	{
		Version: 1,
		Script: `
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
        `,
	},
	{
		Version: 2,
		Script: `
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
        `,
	},
	// Future migrations would be added here, e.g.:
	// {
	//     Version: 3,
	//     Script: `ALTER TABLE hosts ADD COLUMN notes TEXT;`,
	// },
}

// GetMigrations returns the list of all defined migrations.
func GetMigrations() []Migration {
	return allMigrations
}
