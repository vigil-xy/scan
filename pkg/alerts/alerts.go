package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/vigil-sec/vigil/pkg/scanner"
)

// Alerter sends notifications to Slack/Discord
type Alerter struct {
	slackWebhook   string
	discordWebhook string
}

// NewAlerter creates a new alerter
func NewAlerter(slackURL, discordURL string) *Alerter {
	return &Alerter{
		slackWebhook:   slackURL,
		discordWebhook: discordURL,
	}
}

// Notify sends alerts about findings
func (a *Alerter) Notify(findings []scanner.Finding) {
	if len(findings) == 0 {
		return
	}

	// Count by type
	threatCount := len(findings)
	summary := fmt.Sprintf("Vigil detected %d security issue(s)", threatCount)

	// Send to Slack
	if a.slackWebhook != "" {
		a.sendSlack(summary, findings)
	}

	// Send to Discord
	if a.discordWebhook != "" {
		a.sendDiscord(summary, findings)
	}
}

// sendSlack sends a message to Slack
func (a *Alerter) sendSlack(summary string, findings []scanner.Finding) {
	payload := map[string]interface{}{
		"text": summary,
		"attachments": []map[string]interface{}{
			{
				"color": "danger",
				"fields": buildSlackFields(findings),
				"ts":    time.Now().Unix(),
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal Slack payload: %v", err)
		return
	}

	resp, err := http.Post(a.slackWebhook, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("Failed to send Slack alert: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Slack returned status %d", resp.StatusCode)
	}
}

// sendDiscord sends a message to Discord
func (a *Alerter) sendDiscord(summary string, findings []scanner.Finding) {
	embeds := []map[string]interface{}{
		{
			"title":       "🚨 Vigil Security Scan Alert",
			"description": summary,
			"color":       16711680, // Red
			"fields":      buildDiscordFields(findings),
			"timestamp":   time.Now().Format(time.RFC3339),
		},
	}

	payload := map[string]interface{}{
		"content": summary,
		"embeds":  embeds,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal Discord payload: %v", err)
		return
	}

	resp, err := http.Post(a.discordWebhook, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("Failed to send Discord alert: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		log.Printf("Discord returned status %d", resp.StatusCode)
	}
}

// buildSlackFields creates Slack-formatted fields
func buildSlackFields(findings []scanner.Finding) []map[string]interface{} {
	var fields []map[string]interface{}

	threatTypes := make(map[string]int)
	for _, f := range findings {
		threatTypes[f.Type]++
	}

	for threatType, count := range threatTypes {
		fields = append(fields, map[string]interface{}{
			"title": threatType,
			"value": fmt.Sprintf("%d found", count),
			"short": true,
		})
	}

	return fields
}

// buildDiscordFields creates Discord-formatted fields
func buildDiscordFields(findings []scanner.Finding) []map[string]interface{} {
	var fields []map[string]interface{}

	threatTypes := make(map[string]int)
	for _, f := range findings {
		threatTypes[f.Type]++
	}

	for threatType, count := range threatTypes {
		fields = append(fields, map[string]interface{}{
			"name":   threatType,
			"value":  fmt.Sprintf("%d found", count),
			"inline": true,
		})
	}

	return fields
}
