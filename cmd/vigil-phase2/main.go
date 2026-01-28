package main

import (
    "context"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/vigil-sec/vigil/pkg/scanner"
    "github.com/vigil-sec/vigil/pkg/enforcer"
    "github.com/vigil-sec/vigil/pkg/attestation"
    "github.com/vigil-sec/vigil/pkg/alerts"
    "github.com/vigil-sec/vigil/pkg/ebpf"
    "github.com/vigil-sec/vigil/pkg/telemetry"
    "github.com/vigil-sec/vigil/pkg/ledger"
)

// Renamed to avoid conflict with scanner.Scanner
var Version = "0.2.0-phase2"

func main() {
    var (
        _ = flag.Bool("attach-mcp", false, "Attach to MCP server")
        _ = flag.Bool("attach-docker", false, "Attach to Docker daemon")
        hardEnv        = flag.Bool("hard-env", false, "Enable environment variable hardening")
        slackWebhook   = flag.String("slack", "", "Slack webhook URL for alerts")
        discordWebhook = flag.String("discord", "", "Discord webhook URL for alerts")
        dryRun         = flag.Bool("dry-run", false, "Report findings without killing processes")
        debug          = flag.Bool("debug", false, "Enable debug logging")
        monitor        = flag.Bool("monitor", false, "Enable real-time monitoring (requires eBPF)")
        metricsPort    = flag.String("metrics-port", "9090", "Port for metrics endpoint")
        ledgerExport   = flag.String("export-ledger", "", "Export ledger to file (JSON)")
    )
    flag.Parse()

    if *debug {
        log.SetFlags(log.LstdFlags | log.Lshortfile)
    }

    // Initialize components
    sig := attestation.NewSigner()
    alerter := alerts.NewAlerter(*slackWebhook, *discordWebhook)
    s := scanner.NewScanner()
    enf := enforcer.NewEnforcer(*dryRun)
    metrics := telemetry.NewMetrics()
    l := ledger.NewLedger()

    // Initialize eBPF probe if monitoring enabled
    var probe *ebpf.Probe
    if *monitor {
        probe = ebpf.NewProbe()
        probe.Enable()
        if err := probe.Start(); err != nil {
            log.Printf("Warning: eBPF monitoring not available: %v", err)
        } else {
            log.Println("[+] Real-time eBPF monitoring enabled")
            defer probe.Stop()
        }
    }

    // Start metrics HTTP endpoint
    go startMetricsServer(metrics, *metricsPort, l)

    // Set up graceful shutdown
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigChan
        fmt.Println("\n[*] Shutting down...")
        if *ledgerExport != "" {
            exportLedger(l, *ledgerExport)
        }
        os.Exit(0)
    }()

    // Run 30-second scan
    start := time.Now()
    findings := s.Scan(ctx)
    duration := time.Since(start)

    metrics.RecordScan(duration)

    if len(findings) > 0 {
        fmt.Printf("[!] Found %d security issues:\n", len(findings))
        for _, f := range findings {
            fmt.Printf("  - %s: %s (PID: %d)\n", f.Type, f.Description, f.PID)

            // Record in telemetry
            metrics.RecordSecretDetection(f.Type)

            // Add to ledger
            l.Append(ledger.LogEntry{
                Timestamp:   time.Now(),
                EventType:   f.Type,
                Description: f.Description,
                PID:         f.PID,
                Evidence:    f.Evidence,
            })
        }

        // Sign findings
        signedLog := sig.Sign(findings)
        fmt.Printf("[+] Signed log: %s\n", signedLog)

        // Enforce if not dry-run
        if !*dryRun {
            enf.Enforce(ctx, findings)
            metrics.RecordProcessKilled()
        }

        // Alert
        if *slackWebhook != "" {
            alerter.Notify(findings)
            metrics.RecordAlertSent("slack")
        }
        if *discordWebhook != "" {
            alerter.Notify(findings)
            metrics.RecordAlertSent("discord")
        }
    } else {
        fmt.Println("[+] No threats detected")
    }

    // Export ledger if requested
    if *ledgerExport != "" {
        exportLedger(l, *ledgerExport)
    }

    // Apply environment hardening if requested
    if *hardEnv {
        if err := applyEnvHardening(); err != nil {
            log.Printf("Failed to apply env hardening: %v", err)
        }
    }

    // Print metrics summary
    fmt.Println("\n[📊] Metrics Summary:")
    stats := metrics.GetStats()
    for k, v := range stats {
        fmt.Printf("  %s: %v\n", k, v)
    }
}

func applyEnvHardening() error {
    return os.Setenv("VIGIL_ENV", "hard")
}

func startMetricsServer(m *telemetry.Metrics, port string, l *ledger.Ledger) {
    http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        stats := m.GetStats()
        fmt.Fprintf(w, `{"status":"ok","metrics":%+v}`, stats)
    })

    http.HandleFunc("/ledger", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        export := l.ExportJSON()
        fmt.Fprintf(w, `{"ledger":%+v}`, export)
    })

    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        fmt.Fprint(w, `{"status":"ok","version":"0.2.0"}`)
    })

    log.Printf("[📊] Metrics server listening on :%s", port)
    log.Printf("     Metrics: http://localhost:%s/metrics", port)
    log.Printf("     Ledger:  http://localhost:%s/ledger", port)

    if err := http.ListenAndServe(":"+port, nil); err != nil {
        log.Printf("Metrics server error: %v", err)
    }
}

func exportLedger(l *ledger.Ledger, path string) {
    export := l.ExportJSON()
    data, err := json.MarshalIndent(export, "", "  ")
    if err != nil {
        log.Printf("Failed to marshal ledger: %v", err)
        return
    }

    if err := os.WriteFile(path, data, 0600); err != nil {
        log.Printf("Failed to export ledger: %v", err)
        return
    }

    fmt.Printf("[+] Ledger exported to %s\n", path)
}
