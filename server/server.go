package server

import (
	"embed"
	"fmt"
	"gonetmap/livecapture"
	"gonetmap/scanner"
	"gonetmap/storage"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Start accepts the embedded filesystem and starts the web server.
func Start(embeddedTemplates embed.FS) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

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

	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(embeddedTemplates, "templates/*.html"))
	router.SetHTMLTemplate(tmpl)

	// Page routes
	router.GET("/", handleCampaignList)
	router.GET("/compare", handleComparePage)

	campaignRoutes := router.Group("/campaign/:campaignID")
	{
		campaignRoutes.GET("/", handleDashboard)
		campaignRoutes.GET("/hosts/:id", handleHostDetail)
		campaignRoutes.GET("/handshakes", handleHandshakes)
		campaignRoutes.GET("/report/zip", handleReportDownload)
	}

	// API routes
	api := router.Group("/api")
	{
		api.GET("/interfaces", handleGetInterfaces)
		api.DELETE("/campaigns/:campaignID", handleDeleteCampaign)
		api.POST("/compare", handleCompareCampaigns)
		api.GET("/nmap/status", handleGetNmapStatus) // NEW

		scansAPI := api.Group("/scans")
		{
			scansAPI.POST("/live/start", handleStartLiveScan)
			scansAPI.POST("/file/start", handleStartFileScan)
			scansAPI.POST("/nmap/start", handleStartNmapScan) // NEW
			scansAPI.GET("/status", handleGetScanStatus)
			scansAPI.POST("/stop", handleStopScan)
		}

		apiCampaignRoutes := api.Group("/campaign/:campaignID")
		{
			apiCampaignRoutes.GET("/hosts", handleGetHosts)
			apiCampaignRoutes.GET("/hosts/:id/communications", handleGetHostCommunications)
		}
	}

	port := "8080"
	fmt.Printf("✅ Web server running at: http://localhost:%s\n", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("FATAL: Could not start web server: %v", err)
	}
}

// --- Page Handlers ---

func handleCampaignList(c *gin.Context) {
	campaigns, err := storage.ListCampaigns()
	if err != nil {
		c.String(http.StatusInternalServerError, "Could not load campaigns.")
		return
	}
	c.HTML(http.StatusOK, "campaign_list.html", gin.H{
		"Campaigns": campaigns,
	})
}

func handleComparePage(c *gin.Context) {
	campaigns, err := storage.ListCampaigns()
	if err != nil {
		c.String(http.StatusInternalServerError, "Could not load campaigns.")
		return
	}
	baseID, _ := strconv.Atoi(c.DefaultQuery("base", "0"))
	compareID, _ := strconv.Atoi(c.DefaultQuery("compare", "0"))

	c.HTML(http.StatusOK, "compare.html", gin.H{
		"Campaigns":         campaigns,
		"BaseCampaignID":    baseID,
		"CompareCampaignID": compareID,
	})
}

func handleDashboard(c *gin.Context) {
	campaignID, _ := strconv.ParseInt(c.Param("campaignID"), 10, 64)
	campaign, err := storage.GetCampaignByID(campaignID)
	if err != nil {
		c.String(http.StatusInternalServerError, "Could not load campaign details.")
		return
	}
	allCampaigns, err := storage.ListCampaigns()
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
		"AllCampaigns": allCampaigns,
		"Summary":      summary,
	})
}

func handleHostDetail(c *gin.Context) {
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
}

func handleHandshakes(c *gin.Context) {
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
}

func handleReportDownload(c *gin.Context) {
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
}

// --- API Handlers ---

func handleGetNmapStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"isNmapFound": livecapture.IsNmapFound()})
}

func handleGetInterfaces(c *gin.Context) {
	interfaces, err := livecapture.ListInterfaces()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not get interfaces"})
		return
	}
	c.JSON(http.StatusOK, interfaces)
}

func handleDeleteCampaign(c *gin.Context) {
	campaignID, err := strconv.ParseInt(c.Param("campaignID"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid campaign ID"})
		return
	}
	if err := storage.DeleteCampaignByID(campaignID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete campaign"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Campaign deleted successfully"})
}

func handleStartNmapScan(c *gin.Context) {
	var req struct {
		CampaignName string `json:"campaignName"`
		Target       string `json:"target"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}
	_, err := scanner.Manager.StartNmapScanTask(req.Target, req.CampaignName)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Nmap scan started for " + req.CampaignName})
}

func handleStartLiveScan(c *gin.Context) {
	var req struct {
		CampaignName  string `json:"campaignName"`
		InterfaceName string `json:"interfaceName"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}
	_, err := scanner.Manager.StartLiveScanTask(req.CampaignName, req.InterfaceName)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Live scan started for " + req.CampaignName})
}

func handleStartFileScan(c *gin.Context) {
	var req struct {
		CampaignName string `json:"campaignName"`
		Directory    string `json:"directory"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}
	_, err := scanner.Manager.StartFileScanTask(req.CampaignName, req.Directory)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "File scan started for " + req.CampaignName})
}

func handleGetScanStatus(c *gin.Context) {
	isScanning, status := scanner.Manager.GetStatus()
	c.JSON(http.StatusOK, gin.H{"isScanning": isScanning, "status": status})
}

func handleStopScan(c *gin.Context) {
	scanner.Manager.StopScan()
	c.JSON(http.StatusOK, gin.H{"message": "Scan stop request received."})
}

func handleGetHosts(c *gin.Context) {
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
}

func handleGetHostCommunications(c *gin.Context) {
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
}

func handleCompareCampaigns(c *gin.Context) {
	var req struct {
		BaseID    int64 `json:"baseId"`
		CompareID int64 `json:"compareId"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	result, err := CompareCampaigns(req.BaseID, req.CompareID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}
