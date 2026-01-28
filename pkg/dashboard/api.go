package dashboard

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

//go:embed static/index.html
var EmbeddedDashboardHTML string

type ScanResult struct {
	Timestamp string       `json:"timestamp"`
	Ports     []string     `json:"ports"`
	Secrets   []string     `json:"secrets"`
	Processes []string     `json:"processes"`
	AuditLog  []AuditEntry `json:"audit_log"`
}

type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Signature string `json:"signature"`
}

func StartDashboardAPI() error {
	http.HandleFunc("/api/scan", handleScan)
	http.HandleFunc("/", handleDashboard)

	fmt.Println("🚀 Dashboard available at: http://localhost:8080")
	fmt.Println("📊 Press Ctrl+C to stop")

	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return server.ListenAndServe()
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(EmbeddedDashboardHTML))
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	// Mock data for now - will be replaced with actual scanner calls
	ports := scanPorts()
	secrets := scanSecrets()
	processes := scanProcesses()

	result := ScanResult{
		Timestamp: time.Now().Format(time.RFC3339),
		Ports:     ports,
		Secrets:   secrets,
		Processes: processes,
		AuditLog: []AuditEntry{
			{
				Timestamp: time.Now().Format(time.RFC3339),
				Action:    "System scan completed",
				Signature: generateSignature(),
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Mock scanner functions - will be replaced with actual implementations
func scanPorts() []string {
	// This will call pkg/scanner/rogue_ports.go ScanRoguePorts()
	return []string{}
}

func scanSecrets() []string {
	// This will call actual secret scanner
	return []string{}
}

func scanProcesses() []string {
	// This will call actual process scanner
	return []string{}
}

func generateSignature() string {
	// Generate Ed25519 signature
	return fmt.Sprintf("0x%x", time.Now().Unix()%0xffff)
}
