package webenum

import (
	"SnailsHell/model"
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// TakeScreenshot takes a screenshot of a web page using an automated headless browser.
func TakeScreenshot(host *model.Host) {
	// Create a new context for chromedp
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), chromedp.DefaultExecAllocatorOptions[:]...)
	defer cancel()

	// Create a new browser context
	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	defer cancel()

	// Create a timeout for the entire operation
	ctx, cancel = context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	for portID, port := range host.Ports {
		if !isWebPort(portID, port.Service) {
			continue
		}

		protocol := "http"
		if portID == 443 || portID == 8443 || strings.Contains(port.Service, "ssl") || strings.Contains(port.Service, "https") {
			protocol = "https"
		}

		var ip string
		for hostIP := range host.IPv4Addresses {
			ip = hostIP
			break
		}
		if ip == "" {
			continue
		}
		url := fmt.Sprintf("%s://%s:%d", protocol, ip, portID)

		var buf []byte
		// Run the browser tasks
		err := chromedp.Run(ctx,
			chromedp.Navigate(url),
			chromedp.Sleep(2*time.Second), // Wait for the page to render
			chromedp.FullScreenshot(&buf, 90),
		)

		if err != nil {
			log.Printf("Could not take screenshot of %s: %v", url, err)
			continue
		}

		// Add the screenshot to the host
		if host.Screenshots == nil {
			host.Screenshots = make([]model.Screenshot, 0)
		}
		host.Screenshots = append(host.Screenshots, model.Screenshot{
			PortID:      portID,
			ImageData:   buf,
			CaptureTime: time.Now(),
		})
		log.Printf("📸 Successfully took screenshot of %s", url)
	}
}
