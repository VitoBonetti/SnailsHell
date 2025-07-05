package lookups

import (
	"os"
	"testing"
)

// TestLookupVendor is a unit test for the LookupVendor function.
func TestLookupVendor(t *testing.T) {
	// --- Test Setup ---
	// This setup is designed to be safe and work across different OSes.
	// It temporarily replaces the real oui.txt with a small, controlled version for testing.

	testOuiData := `00-50-C2 (hex)		VMware, Inc.
8C-EA-B4 (hex)		Apple, Inc.`
	testFilePath := "oui.txt"

	// 1. Backup the original oui.txt if it exists.
	originalData, err := os.ReadFile(testFilePath)
	originalExists := !os.IsNotExist(err)
	if err != nil && originalExists {
		t.Fatalf("Failed to read original oui.txt for backup: %v", err)
	}

	// 2. Write the temporary test data to oui.txt.
	if err := os.WriteFile(testFilePath, []byte(testOuiData), 0644); err != nil {
		t.Fatalf("Failed to write temporary oui.txt: %v", err)
	}

	// 3. Defer the cleanup logic to run after the test finishes.
	defer func() {
		// Restore the original oui.txt if it was backed up.
		if originalExists {
			if err := os.WriteFile(testFilePath, originalData, 0644); err != nil {
				t.Fatalf("Failed to restore original oui.txt: %v", err)
			}
		} else {
			// If it didn't exist before, remove the test file.
			os.Remove(testFilePath)
		}
	}()

	// 4. Initialize the MAC lookup service with our test data.
	if err := InitMac(); err != nil {
		t.Fatalf("InitMac() failed: %v", err)
	}

	// --- Test Cases ---

	// t.Run allows grouping tests and gives clearer output on failure.
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
		if err == nil {
			t.Errorf("LookupVendor for %s was expected to fail, but it succeeded.", mac)
		}
		if vendor != expectedVendor {
			t.Errorf("LookupVendor for %s was incorrect, got: %s, want: %s.", mac, vendor, expectedVendor)
		}
	})
}
