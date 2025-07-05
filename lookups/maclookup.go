package lookups

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var ouiData = make(map[string]string)

// InitMac loads the OUI database from the embedded file.
func InitMac() error {
	file, err := os.Open("oui.txt")
	if err != nil {
		return fmt.Errorf("could not open oui.txt: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "(hex)") {
			parts := strings.SplitN(line, "(hex)", 2)
			if len(parts) == 2 {
				prefix := strings.TrimSpace(parts[0])
				prefix = strings.ReplaceAll(prefix, "-", ":")
				vendor := strings.TrimSpace(parts[1])
				ouiData[prefix] = vendor
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading oui.txt: %w", err)
	}
	fmt.Println("✅ OUI database loaded successfully for local MAC lookups.")
	return nil
}

// LookupVendor finds the vendor for a given MAC address.
func LookupVendor(mac string) (string, error) {
	if len(mac) < 8 {
		return "Unknown Vendor", fmt.Errorf("invalid MAC address format")
	}
	prefix := strings.ToUpper(mac[:8])
	vendor, found := ouiData[prefix]
	if !found {
		return "Unknown Vendor", fmt.Errorf("vendor not found for prefix %s", prefix)
	}
	return vendor, nil
}
