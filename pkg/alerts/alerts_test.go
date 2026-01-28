package alerts

import (
	"testing"

	"github.com/vigil-sec/vigil/pkg/scanner"
)

func TestAlerterCreation(t *testing.T) {
	alerter := NewAlerter("https://test-slack.com", "https://test-discord.com")

	if alerter == nil {
		t.Error("Alerter is nil")
	}

	if alerter.slackWebhook != "https://test-slack.com" {
		t.Error("Slack webhook not set correctly")
	}

	if alerter.discordWebhook != "https://test-discord.com" {
		t.Error("Discord webhook not set correctly")
	}
}

func TestAlerterWithEmptyWebhooks(t *testing.T) {
	alerter := NewAlerter("", "")

	findings := []scanner.Finding{
		{Type: "TEST", Description: "Test finding"},
	}

	// Should not panic with empty webhooks
	alerter.Notify(findings)
}

func TestAlerterWithNoFindings(t *testing.T) {
	alerter := NewAlerter("https://test-slack.com", "https://test-discord.com")

	findings := []scanner.Finding{}

	// Should handle empty findings gracefully
	alerter.Notify(findings)
}

func TestAlerterWithFindings(t *testing.T) {
	alerter := NewAlerter("https://hooks.slack.com/test", "https://discord.com/test")

	findings := []scanner.Finding{
		{Type: "THREAT1", Description: "First threat"},
		{Type: "THREAT2", Description: "Second threat"},
		{Type: "THREAT1", Description: "Third threat (duplicate type)"},
	}

	// Should not panic - actual webhook sending will fail safely in test
	alerter.Notify(findings)
}

func TestSlackFieldsGeneration(t *testing.T) {
	findings := []scanner.Finding{
		{Type: "EXPOSED_SECRET", Description: "Secret 1"},
		{Type: "EXPOSED_SECRET", Description: "Secret 2"},
		{Type: "HIJACKED_PORT", Description: "Port 1"},
	}

	fields := buildSlackFields(findings)

	if len(fields) != 2 {
		t.Errorf("Expected 2 threat types, got %d", len(fields))
	}
}

func TestDiscordFieldsGeneration(t *testing.T) {
	findings := []scanner.Finding{
		{Type: "EXPOSED_SECRET", Description: "Secret 1"},
		{Type: "EXPOSED_SECRET", Description: "Secret 2"},
		{Type: "HIJACKED_PORT", Description: "Port 1"},
	}

	fields := buildDiscordFields(findings)

	if len(fields) != 2 {
		t.Errorf("Expected 2 threat types, got %d", len(fields))
	}
}
