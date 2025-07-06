package lookups

import (
	"os"
	"testing"

	"github.com/klauspost/oui"
)

// TestLookupVendor is a unit test for the LookupVendor function.
func TestLookupVendor(t *testing.T) {
	// --- Test Setup ---
	// The new maclookup implementation uses a real parsing library,
	// which is stricter about the file format. This test data
	// is a minimal but valid OUI file format that the library can parse.
	testOuiData := `
00-50-C2   (hex)		VMware, Inc.
0050C2     (base 16)		VMware, Inc.

8C-EA-B4   (hex)		Apple, Inc.
8CEAB4     (base 16)		Apple, Inc.
`
	// Create a temporary file for the test.
	// t.TempDir() automatically creates a temporary directory that is cleaned up
	// after the test, which is safer and cleaner.
	tempDir := t.TempDir()
	testFilePath := tempDir + "/oui.txt"

	if err := os.WriteFile(testFilePath, []byte(testOuiData), 0644); err != nil {
		t.Fatalf("Failed to write temporary oui.txt: %v", err)
	}

	// --- Test Initialization ---
	// We need to temporarily replace the global 'db' with a new one
	// loaded from our test file.
	var err error
	db, err = oui.OpenFile(testFilePath) // Use the library's OpenFile directly
	if err != nil {
		t.Fatalf("Failed to open test OUI database: %v", err)
	}

	// --- Test Cases ---

	t.Run("KnownVendor_Apple", func(t *testing.T) {
		mac := "8C:EA:B4:12:34:56"
		expectedVendor := "Apple, Inc."
		vendor, err := LookupVendor(mac)
		if err != nil {
			t.Errorf("LookupVendor for %s failed unexpectedly: %v", mac, err)
		}
		if vendor != expectedVendor {
			t.Errorf("LookupVendor for %s was incorrect, got: %s, want: %s.", mac, vendor, expectedVendor)
		}
	})

	t.Run("KnownVendor_VMware", func(t *testing.T) {
		mac := "00:50:C2:78:9A:BC"
		expectedVendor := "VMware, Inc."
		vendor, err := LookupVendor(mac)
		if err != nil {
			t.Errorf("LookupVendor for %s failed unexpectedly: %v", mac, err)
		}
		if vendor != expectedVendor {
			t.Errorf("LookupVendor for %s was incorrect, got: %s, want: %s.", mac, vendor, expectedVendor)
		}
	})

	t.Run("UnknownVendor", func(t *testing.T) {
		mac := "00:11:22:33:44:55"
		expectedVendor := "Unknown Vendor"
		vendor, err := LookupVendor(mac)
		// We expect an error when the vendor is not found.
		if err == nil {
			t.Errorf("LookupVendor for %s was expected to fail, but it succeeded.", mac)
		}
		if vendor != expectedVendor {
			t.Errorf("LookupVendor for %s was incorrect, got: %s, want: %s.", mac, vendor, expectedVendor)
		}
	})
}
