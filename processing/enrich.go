package processing

import (
	"fmt"
	"gonetmap/lookups"
	"gonetmap/model"
	"log"
)

// EnrichWithLookups performs GeoIP and MAC vendor lookups.
func EnrichWithLookups(networkMap *model.NetworkMap, summary *model.PcapSummary) {
	fmt.Println("--- Performing Geolocation Lookups ---")
	geoCache := make(map[string]*model.GeoInfo)
	for _, host := range networkMap.Hosts {
		for _, comm := range host.Communications {
			if geoInfo, found := geoCache[comm.CounterpartIP]; found {
				comm.Geo = geoInfo
				continue
			}
			geoInfo, err := lookups.LookupIP(comm.CounterpartIP)
			if err != nil {
				log.Printf("Could not get geo info for %s: %v", comm.CounterpartIP, err)
			}
			if geoInfo != nil {
				fmt.Printf("  -> Found %s -> %s, %s (%s)\n", comm.CounterpartIP, geoInfo.City, geoInfo.Country, geoInfo.ISP)
				comm.Geo = geoInfo
				geoCache[comm.CounterpartIP] = geoInfo
			}
		}
	}
	fmt.Println("✅ Geolocation enrichment complete.")

	fmt.Println("\n--- Performing Local MAC Vendor Lookups ---")
	allMacsToLookup := make(map[string]string)
	for mac := range summary.UnidentifiedMACs {
		allMacsToLookup[mac] = ""
	}
	for _, host := range networkMap.Hosts {
		if (host.Fingerprint == nil || host.Fingerprint.Vendor == "") && host.MACAddress != "" {
			allMacsToLookup[host.MACAddress] = ""
		}
	}

	if len(allMacsToLookup) > 0 {
		fmt.Printf("  -> Found %d unique MACs to look up.\n", len(allMacsToLookup))
		for mac := range allMacsToLookup {
			vendor, err := lookups.LookupVendor(mac)
			if err == nil && vendor != "Unknown Vendor" {
				allMacsToLookup[mac] = vendor
			}
		}
		for mac, vendor := range allMacsToLookup {
			if vendor == "" {
				continue
			}
			if host, ok := networkMap.Hosts[mac]; ok {
				if host.Fingerprint == nil {
					host.Fingerprint = &model.Fingerprint{}
				}
				host.Fingerprint.Vendor = vendor
			}
			if _, ok := summary.UnidentifiedMACs[mac]; ok {
				summary.UnidentifiedMACs[mac] = vendor
			}
		}
		fmt.Println("✅ Local MAC Vendor lookup complete.")
	} else {
		fmt.Println("No new MAC addresses to look up.")
	}
}
