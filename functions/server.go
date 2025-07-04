package functions

import (
	"embed"
	"fmt"
	"gonetmap/storage"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// StartServer now accepts the embedded filesystem
func StartServer(embeddedTemplates embed.FS) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// Define all custom functions for the templates to use.
	funcMap := template.FuncMap{
		"replace": func(input, from, to string) string {
			return strings.ReplaceAll(input, from, to)
		},
		"add": func(a, b int) int {
			return a + b
		},
		"makeSlice": func(n int) []struct{} {
			return make([]struct{}, n)
		},
		"upper": strings.ToUpper,
		"default": func(dflt, val string) string {
			if val == "" {
				return dflt
			}
			return val
		},
	}

	// Parse the templates from the passed-in filesystem.
	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(embeddedTemplates, "templates/*.html"))
	router.SetHTMLTemplate(tmpl)

	// --- Route for the home page (lists all campaigns) ---
	router.GET("/", func(c *gin.Context) {
		campaigns, err := storage.ListCampaigns()
		if err != nil {
			c.String(http.StatusInternalServerError, "Could not load campaigns.")
			return
		}
		c.HTML(http.StatusOK, "campaign_list.html", gin.H{
			"Campaigns": campaigns,
		})
	})

	// --- Group all campaign-specific page routes ---
	campaignRoutes := router.Group("/campaign/:campaignID")
	{
		// Dashboard Page
		campaignRoutes.GET("/", func(c *gin.Context) {
			campaignID, _ := strconv.ParseInt(c.Param("campaignID"), 10, 64)
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
			summary, err := storage.GetDashboardSummary(campaignID)
			if err != nil {
				c.String(http.StatusInternalServerError, "Could not load dashboard summary.")
				return
			}

			c.HTML(http.StatusOK, "dashboard.html", gin.H{
				"Campaign":     campaign,
				"AllCampaigns": all_campaigns,
				"Summary":      summary,
			})
		})

		// Host Detail Page
		campaignRoutes.GET("/hosts/:id", func(c *gin.Context) {
			campaignID, _ := strconv.ParseInt(c.Param("campaignID"), 10, 64)
			hostID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
			host, err := storage.GetHostByID(hostID, campaignID)
			if err != nil {
				c.String(http.StatusNotFound, "Host not found")
				return
			}
			c.HTML(http.StatusOK, "host_detail.html", gin.H{
				"Host":       host,
				"CampaignID": campaignID,
			})
		})

		// Handshakes Page (Paginated)
		campaignRoutes.GET("/handshakes", func(c *gin.Context) {
			campaignID, _ := strconv.ParseInt(c.Param("campaignID"), 10, 64)
			campaign, err := storage.GetCampaignByID(campaignID)
			if err != nil {
				c.String(http.StatusInternalServerError, "Could not load campaign details.")
				return
			}

			page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
			if page < 1 {
				page = 1
			}
			const pageSize = 10
			offset := (page - 1) * pageSize
			totalHandshakes, err := storage.CountHandshakesByCampaign(campaignID)
			if err != nil {
				c.String(http.StatusInternalServerError, "Could not count handshakes.")
				return
			}
			totalPages := (totalHandshakes + pageSize - 1) / pageSize
			if totalPages == 0 && totalHandshakes > 0 {
				totalPages = 1
			}

			handshakes, err := storage.GetHandshakesByCampaignPaginated(campaignID, pageSize, offset)
			if err != nil {
				c.String(http.StatusInternalServerError, "Could not load handshakes.")
				return
			}
			c.HTML(http.StatusOK, "handshakes.html", gin.H{
				"Campaign":    campaign,
				"Handshakes":  handshakes,
				"TotalPages":  totalPages,
				"CurrentPage": page,
			})
		})

		// Route for report download
		campaignRoutes.GET("/report/zip", func(c *gin.Context) {
			campaignID, _ := strconv.ParseInt(c.Param("campaignID"), 10, 64)
			campaign, err := storage.GetCampaignByID(campaignID)
			if err != nil {
				c.String(http.StatusNotFound, "Campaign not found")
				return
			}

			zipData, err := GenerateReportZip(campaignID)
			if err != nil {
				c.String(http.StatusInternalServerError, "Could not generate ZIP report.")
				return
			}

			filename := fmt.Sprintf("gonetmap_report_%s_%s.zip", strings.ReplaceAll(campaign.Name, " ", "_"), time.Now().Format("2006-01-02"))
			c.Header("Content-Disposition", "attachment; filename="+filename)
			c.Data(http.StatusOK, "application/zip", zipData)
		})
	}

	// --- Group all campaign-specific API endpoints ---
	apiRoutes := router.Group("/api/campaign/:campaignID")
	{
		// API: Get Hosts for Dashboard with Search and Filter
		apiRoutes.GET("/hosts", func(c *gin.Context) {
			campaignID, _ := strconv.ParseInt(c.Param("campaignID"), 10, 64)
			page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
			if page < 1 {
				page = 1
			}
			searchQuery := c.DefaultQuery("search", "")
			filterQuery := c.DefaultQuery("filter", "all")

			const pageSize = 21
			offset := (page - 1) * pageSize

			hosts, totalHosts, err := storage.GetHostsByCampaignPaginated(campaignID, pageSize, offset, searchQuery, filterQuery)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not retrieve hosts: " + err.Error()})
				return
			}

			totalPages := (totalHosts + pageSize - 1) / pageSize
			if totalPages == 0 && totalHosts > 0 {
				totalPages = 1
			}

			c.JSON(http.StatusOK, gin.H{
				"hosts":       hosts,
				"currentPage": page,
				"totalPages":  totalPages,
			})
		})

		// API: Get Communications for Graph
		apiRoutes.GET("/hosts/:id/communications", func(c *gin.Context) {
			hostID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
			campaignID, _ := strconv.ParseInt(c.Param("campaignID"), 10, 64)
			host, err := storage.GetHostByID(hostID, campaignID)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Host not found"})
				return
			}

			type Node struct {
				ID    string `json:"id"`
				Label string `json:"label"`
				Title string `json:"title,omitempty"`
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
			nodes = append(nodes, Node{
				ID:    "host",
				Label: host.MACAddress,
				Shape: "database",
				Color: "#f39c12",
			})
			for ip, comm := range host.Communications {
				nodeID := strings.ReplaceAll(ip, ".", "_")
				label := ip
				tooltip := ip
				var locationParts []string
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
	}

	port := "8080"
	fmt.Printf("✅ Starting web server. View your campaigns at: http://localhost:%s\n", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("FATAL: Could not start web server: %v", err)
	}
}
