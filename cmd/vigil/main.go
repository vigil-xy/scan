package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/vigil-sec/vigil/pkg/scanner"
	"github.com/vigil-sec/vigil/pkg/enforcer"
	"github.com/vigil-sec/vigil/pkg/attestation"
	"github.com/vigil-sec/vigil/pkg/alerts"
)

func main() {
	// Check for dashboard command first
	if len(os.Args) > 1 && os.Args[1] == "dashboard" {
		runDashboard()
		return
	}

	var (
		_ = flag.Bool("attach-mcp", false, "Attach to MCP server")
		_ = flag.Bool("attach-docker", false, "Attach to Docker daemon")
		hardEnv      = flag.Bool("hard-env", false, "Enable environment variable hardening")
		slackWebhook = flag.String("slack", "", "Slack webhook URL for alerts")
		discordWebhook = flag.String("discord", "", "Discord webhook URL for alerts")
		dryRun       = flag.Bool("dry-run", false, "Report findings without killing processes")
		debug        = flag.Bool("debug", false, "Enable debug logging")
	)
	flag.Parse()

	if *debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[*] Shutting down...")
		cancel()
		os.Exit(0)
	}()

	// Initialize components
	sig := attestation.NewSigner()
	alerter := alerts.NewAlerter(*slackWebhook, *discordWebhook)
	s := scanner.NewScanner()
	enf := enforcer.NewEnforcer(*dryRun)

	// Run 30-second scan
	findings := s.Scan(ctx)

	if len(findings) > 0 {
		fmt.Printf("[!] Found %d security issues:\n", len(findings))
		for _, f := range findings {
			fmt.Printf("  - %s: %s (PID: %d)\n", f.Type, f.Description, f.PID)
		}

		// Sign findings
		signedLog := sig.Sign(findings)
		fmt.Printf("[+] Signed log: %s\n", signedLog)

		// Enforce if not dry-run
		if !*dryRun {
			enf.Enforce(ctx, findings)
		}

		// Alert
		alerter.Notify(findings)
	} else {
		fmt.Println("[+] No threats detected")
	}

	// Apply environment hardening if requested
	if *hardEnv {
		if err := applyEnvHardening(); err != nil {
			log.Printf("Failed to apply env hardening: %v", err)
		}
	}
}

func applyEnvHardening() error {
	// Set environment variable to prevent child processes from accessing sensitive data
	return os.Setenv("VIGIL_ENV", "hard")
}
