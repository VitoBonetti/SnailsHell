package processing

import (
	"SnailsHell/model"
	"testing"
)

func TestCheckForSecrets(t *testing.T) {
	testCases := []struct {
		name          string
		payload       string
		expectedType  string
		expectedValue string
		shouldFind    bool
	}{
		{
			name:          "Find API Key",
			payload:       `{"user": "test", "apikey": "ab123cdef456ghi789jklmno0123pqr456stu"}`,
			expectedType:  "API Key/Token",
			expectedValue: "ab123cdef456ghi789jklmno0123pqr456stu",
			shouldFind:    true,
		},
		{
			name:          "Find Bearer Token",
			payload:       "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expectedType:  "Bearer Token",
			expectedValue: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			shouldFind:    true,
		},
		{
			name:       "No Secrets",
			payload:    "this is a normal http request with no secrets",
			shouldFind: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			summary := model.NewPcapSummary()
			checkForSecrets([]byte(tc.payload), "AA:BB:CC:DD:EE:FF", "192.168.1.1", summary, "test.pcap")

			if tc.shouldFind {
				if len(summary.Credentials) != 1 {
					t.Fatalf("Expected to find 1 credential, but found %d", len(summary.Credentials))
				}
				cred := summary.Credentials[0]
				if cred.Type != tc.expectedType {
					t.Errorf("Expected type %s, but got %s", tc.expectedType, cred.Type)
				}
				if cred.Value != tc.expectedValue {
					t.Errorf("Expected value %s, but got %s", tc.expectedValue, cred.Value)
				}
			} else {
				if len(summary.Credentials) > 0 {
					t.Errorf("Expected to find 0 credentials, but found %d", len(summary.Credentials))
				}
			}
		})
	}
}
