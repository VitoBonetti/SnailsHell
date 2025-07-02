package functions

import (
	"fmt"
	"gonetmap/storage"
	"html/template"
	"net/http"
	"strconv" // <-- Make sure this is imported
	"strings"

	"github.com/gin-gonic/gin"
)

// StartServer initializes and runs the web server.
func StartServer(campaignID int64) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// This makes the "replace" function available in your HTML.
	router.SetFuncMap(template.FuncMap{
		"replace": func(input, from, to string) string {
			return strings.ReplaceAll(input, from, to)
		},
		// NEW: Add these functions for pagination logic in the template
		"add": func(a, b int) int {
			return a + b
		},
		"makeSlice": func(n int) []struct{} {
			return make([]struct{}, n)
		},
	})

	// Tell Gin where to find all template files.
	router.LoadHTMLGlob("templates/*")

	// In the StartServer function, update the GET "/" route handler
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
		// NEW: Get dashboard summary
		summary, err := storage.GetDashboardSummary(campaignID)
		if err != nil {
			c.String(http.StatusInternalServerError, "Could not load dashboard summary.")
			return
		}

		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"Campaign":     campaign,
			"AllCampaigns": all_campaigns,
			"Summary":      summary, // NEW
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
			c.String(http.StatusNotFound, "Host not found")
			return
		}

		// Pass the host data AND the campaignID to the template
		c.HTML(http.StatusOK, "host_detail.html", gin.H{
			"Host":       host,
			"CampaignID": campaignID, // <-- Pass the ID for the "back" button
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
		const pageSize = 24
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

	router.GET("/hosts/:id/communications_graph", func(c *gin.Context) {
		hostID, _ := c.Params.Get("id")
		c.HTML(http.StatusOK, "communications_graph.html", gin.H{
			"HostID": hostID,
		})
	})

	router.GET("/api/hosts/:id/communications", func(c *gin.Context) {
		hostID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
		host, err := storage.GetHostByID(hostID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Host not found"})
			return
		}

		// Define structs for the vis.js format
		type Node struct {
			ID    string `json:"id"`
			Label string `json:"label"`
			Title string `json:"title,omitempty"` // Tooltip
			Shape string `json:"shape"`
			Color string `json:"color,omitempty"`
		}
		type Edge struct {
			From  string `json:"from"`
			To    string `json:"to"`
			Label string `json:"label"`
		}

		nodes := []Node{}
		edges := []Edge{}

		// Add the central host node
		nodes = append(nodes, Node{
			ID:    "host",
			Label: host.MACAddress,
			Shape: "database",
			Color: "#f39c12", // 1. CHANGED: A lighter, more readable orange
		})

		// Add a node and an edge for each communication
		for ip, comm := range host.Communications {
			nodeID := strings.ReplaceAll(ip, ".", "_")
			label := ip
			tooltip := ip
			var locationParts []string // 2. NEW: Smarter way to build the location string

			if comm.Geo != nil {
				if comm.Geo.City != "" {
					locationParts = append(locationParts, comm.Geo.City)
				}
				if comm.Geo.Country != "" {
					locationParts = append(locationParts, comm.Geo.Country)
				}
				if comm.Geo.ISP != "" {
					tooltip += "\nISP: " + comm.Geo.ISP
				}
			}

			if len(locationParts) > 0 {
				label += "\n" + strings.Join(locationParts, ", ")
			}

			nodes = append(nodes, Node{
				ID:    nodeID,
				Label: label,
				Title: tooltip,
				Shape: "box",
			})

			edges = append(edges, Edge{
				From:  "host",
				To:    nodeID,
				Label: fmt.Sprintf("%d pkts", comm.PacketCount),
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"nodes": nodes,
			"edges": edges,
		})
	})

	// NEW: Route for the handshakes page
	router.GET("/handshakes", func(c *gin.Context) {
		// 1. Get the requested page number from the URL, default to page 1
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		if page < 1 {
			page = 1
		}

		// 2. Set the number of items per page
		const pageSize = 10
		offset := (page - 1) * pageSize

		// 3. Get the total number of handshakes to calculate total pages
		totalHandshakes, err := storage.CountHandshakesByCampaign(campaignID)
		if err != nil {
			c.String(http.StatusInternalServerError, "Could not count handshakes.")
			return
		}
		totalPages := (totalHandshakes + pageSize - 1) / pageSize

		// 4. Get the paginated handshake data
		handshakes, err := storage.GetHandshakesByCampaignPaginated(campaignID, pageSize, offset)
		if err != nil {
			c.String(http.StatusInternalServerError, "Could not load handshakes.")
			return
		}

		// 5. Pass all the data to the template
		c.HTML(http.StatusOK, "handshakes.html", gin.H{
			"Handshakes":  handshakes,
			"CampaignID":  campaignID,
			"TotalPages":  totalPages,
			"CurrentPage": page,
		})
	})

	port := "8080"
	fmt.Printf("✅ Starting web server. View your campaign at: http://localhost:%s\n", port)
	router.Run(":" + port)
}
