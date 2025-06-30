package functions

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/klauspost/oui"
)

// db will hold the loaded OUI database in memory.
var db oui.OuiDB

// The official source URL for the OUI database file.
const ouiURL = "http://standards-oui.ieee.org/oui.txt"

// Init loads the OUI database, downloading it if necessary.
func Init() error {
	const filename = "oui.txt"

	// Check if the database file already exists.
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		fmt.Printf("OUI database (%s) not found. Downloading latest version...\n", filename)
		if err := downloadFile(filename, ouiURL); err != nil {
			return fmt.Errorf("could not download OUI database: %w", err)
		}
		fmt.Println("✅ OUI database downloaded successfully.")
	}

	// Now that we know the file exists, open it.
	var err error
	db, err = oui.OpenFile(filename)
	if err != nil {
		return fmt.Errorf("failed to open OUI database file '%s': %w", filename, err)
	}

	fmt.Println("✅ OUI database loaded successfully for local MAC lookups.")
	return nil
}

// LookupVendor performs a fast, local lookup for the vendor of a given MAC address.
func LookupVendor(mac string) (string, error) {
	if db == nil {
		return "", fmt.Errorf("OUI database not initialized")
	}

	entry, err := db.Query(mac)
	if err != nil {
		// This error means the prefix was not found in the database.
		return "Unknown Vendor", nil
	}

	return entry.Manufacturer, nil
}

// downloadFile is a helper function to download a file from a URL.
func downloadFile(filepath string, url string) error {
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}
