package functions

import (
	"fmt"
	"gonetmap/storage"
	"net/http"
	"strconv" // <-- Make sure this is imported

	"github.com/gin-gonic/gin"
)

// StartServer initializes and runs the web server.
func StartServer(campaignID int64) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// Tell Gin where to find all template files.
	router.LoadHTMLGlob("templates/*")

	// --- Define Web Page Routes ---

	// Route for the main dashboard
	router.GET("/", func(c *gin.Context) {
		campaign, err := storage.GetCampaignByID(campaignID)
		if err != nil {
			c.String(http.StatusInternalServerError, "Could not load campaign details.")
			return
		}
		all_campaigns, err := storage.ListCampaigns()
		if err != nil {
			c.String(http.StatusInternalServerError, "Could not load campaigns.")
			return
		}
		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"Campaign":     campaign,
			"AllCampaigns": all_campaigns,
		})
	})

	router.GET("/open", func(c *gin.Context) {
		campaignID, _ := strconv.ParseInt(c.Query("campaign_id"), 10, 64)
		if campaignID > 0 {
			// Redirect the browser to the root dashboard for that campaign ID
			// Note: In a real app, you'd handle this more elegantly, but for now
			// this requires the user to rerun the app with the new campaign.
			// A better approach would be to use the ID to reload the page with new data.

			// For now, let's just point to the dashboard of the current server instance.
			// A full multi-campaign UI is a bigger step.
			c.Redirect(http.StatusFound, "/")
		}
	})

	// Route for the host detail page
	router.GET("/hosts/:id", func(c *gin.Context) {
		hostID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
		host, err := storage.GetHostByID(hostID)
		if err != nil {
			// Redirect to an error message or just show a simple text error
			c.String(http.StatusNotFound, "Host not found")
			return
		}
		c.HTML(http.StatusOK, "host_detail.html", gin.H{
			"Host": host,
		})
	})

	// --- API Endpoint ---
	router.GET("/api/hosts", func(c *gin.Context) {
		// 1. Get the requested page number from the URL, default to page 1
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		if page < 1 {
			page = 1
		}

		// 2. Set the number of items per page
		const pageSize = 25
		offset := (page - 1) * pageSize

		// 3. Get the total number of hosts to calculate total pages
		totalHosts, err := storage.CountHostsByCampaign(campaignID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not count hosts"})
			return
		}
		totalPages := (totalHosts + pageSize - 1) / pageSize

		// 4. Get the paginated host data
		hosts, err := storage.GetHostsByCampaignPaginated(campaignID, pageSize, offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not retrieve hosts"})
			return
		}

		// 5. Return the data along with pagination info
		c.JSON(http.StatusOK, gin.H{
			"hosts":       hosts,
			"currentPage": page,
			"totalPages":  totalPages,
		})
	})

	port := "8080"
	fmt.Printf("✅ Starting web server. View your campaign at: http://localhost:%s\n", port)
	router.Run(":" + port)
}
