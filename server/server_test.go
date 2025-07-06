package server

import (
	"SnailsHell/config"
	"SnailsHell/model"
	"SnailsHell/storage"
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// setupTestRouter initializes an in-memory database and the full Gin router for testing.
func setupTestRouter(t *testing.T) *gin.Engine {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Initialize a test config
	config.Cfg = &config.Config{}
	config.Cfg.Application.Name = "TestApp"

	// Initialize a test database in memory
	if err := storage.InitDB("file::memory:?cache=shared"); err != nil {
		t.Fatalf("Failed to initialize in-memory database: %v", err)
	}

	// Create a new Gin engine
	router := gin.New()

	// Register the specific handler we want to test
	api := router.Group("/api")
	{
		api.GET("/screenshot/:id", handleGetScreenshot)
	}

	return router
}

func TestGetScreenshotAPI(t *testing.T) {
	router := setupTestRouter(t)

	// --- 1. Seed the database with a screenshot ---
	campaignID, _ := storage.GetOrCreateCampaign("API Screenshot Test")
	networkMap := model.NewNetworkMap()
	host := model.NewHost("12:34:56:78:90:AB")
	host.Ports[443] = model.Port{ID: 443, Protocol: "tcp", State: "open"}
	testImage := []byte("this-is-a-real-png-i-swear")
	host.Screenshots = []model.Screenshot{{PortID: 443, ImageData: testImage}}
	networkMap.Hosts[host.MACAddress] = host

	if err := storage.SaveScanResults(campaignID, networkMap, &model.PcapSummary{}); err != nil {
		t.Fatalf("Failed to save test data: %v", err)
	}

	// Get the ID of the saved screenshot
	var screenshotID int64
	err := storage.DB.QueryRow("SELECT id FROM screenshots").Scan(&screenshotID)
	if err != nil || screenshotID == 0 {
		t.Fatalf("Failed to get screenshot ID from test database: %v", err)
	}

	// --- 2. Make a request to the test server ---
	req, _ := http.NewRequest("GET", fmt.Sprintf("/api/screenshot/%d", screenshotID), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// --- 3. Assert the response ---
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body
	body, _ := ioutil.ReadAll(rr.Body)
	if !bytes.Equal(body, testImage) {
		t.Errorf("Handler returned unexpected body: got %s want %s", string(body), string(testImage))
	}

	// Check the content type header
	expectedContentType := "image/png"
	if ctype := rr.Header().Get("Content-Type"); ctype != expectedContentType {
		t.Errorf("Handler returned wrong content type: got %s want %s", ctype, expectedContentType)
	}
}
