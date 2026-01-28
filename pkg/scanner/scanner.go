package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Finding represents a security finding
type Finding struct {
	Type        string
	Description string
	PID         int
	Timestamp   time.Time
	Evidence    string
}

// Scanner performs the 30-second security scan
type Scanner struct {
	secretPatterns []*regexp.Regexp
	blacklistPorts map[int]string
}

// NewScanner creates a new scanner with default patterns
func NewScanner() *Scanner {
	return &Scanner{
		secretPatterns: []*regexp.Regexp{
			// AWS keys
			regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			// GitHub tokens
			regexp.MustCompile(`ghp_[A-Za-z0-9_]{36}`),
			regexp.MustCompile(`ghu_[A-Za-z0-9_]{36}`),
			// Generic bearer tokens
			regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]+`),
			// API keys
			regexp.MustCompile(`(?i)api[_-]?key[\s:=]+[A-Za-z0-9._\-]{20,}`),
		},
		blacklistPorts: map[int]string{
			11434: "Ollama (prompt injection risk)",
			8000: "Common service hijack vector",
			5000: "Flask debug (if exposed)",
		},
	}
}

// Scan performs the security scan
func (s *Scanner) Scan(ctx context.Context) []Finding {
	var findings []Finding

	// Scan environment variables
	findings = append(findings, s.scanEnvironment()...)

	// Scan listening ports
	findings = append(findings, s.scanPorts()...)

	// Scan process tree
	findings = append(findings, s.scanProcessTree()...)

	// Scan loaded libraries (basic check)
	findings = append(findings, s.scanLoadedLibs()...)

	return findings
}

// scanEnvironment checks for exposed secrets in environment
func (s *Scanner) scanEnvironment() []Finding {
	var findings []Finding
	pid := os.Getpid()

	for _, envVar := range os.Environ() {
		for _, pattern := range s.secretPatterns {
			if pattern.MatchString(envVar) {
				key := strings.Split(envVar, "=")[0]
				findings = append(findings, Finding{
					Type:        "EXPOSED_SECRET",
					Description: fmt.Sprintf("Sensitive data in environment variable: %s", key),
					PID:         pid,
					Timestamp:   time.Now(),
					Evidence:    key,
				})
				break
			}
		}
	}

	return findings
}

// scanPorts checks for hijacked or suspicious listening ports
func (s *Scanner) scanPorts() []Finding {
	var findings []Finding

	// Use netstat to find listening ports
	cmd := exec.Command("netstat", "-tlnp")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback to ss if netstat fails
		cmd = exec.Command("ss", "-tlnp")
		output, _ = cmd.CombinedOutput()
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Parse listening ports
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		localAddr := parts[len(parts)-2]
		if strings.Contains(localAddr, ":") {
			portParts := strings.Split(localAddr, ":")
			if len(portParts) > 0 {
				// Check if it's a blacklisted port
				portStr := portParts[len(portParts)-1]
				var port int
				fmt.Sscanf(portStr, "%d", &port)

				if reason, exists := s.blacklistPorts[port]; exists {
					findings = append(findings, Finding{
						Type:        "HIJACKED_PORT",
						Description: fmt.Sprintf("Port %d listening (suspicious): %s", port, reason),
						PID:         0,
						Timestamp:   time.Now(),
						Evidence:    localAddr,
					})
				}
			}
		}
	}

	return findings
}

// scanProcessTree checks for suspicious processes
func (s *Scanner) scanProcessTree() []Finding {
	var findings []Finding

	// Check for processes with suspicious environment
	cmd := exec.Command("ps", "auxe")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return findings
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Check for exposed secrets in process environment
		for _, pattern := range s.secretPatterns {
			if pattern.MatchString(line) {
				findings = append(findings, Finding{
					Type:        "EXPOSED_SECRET_PROCESS",
					Description: "Secret found in process environment or command line",
					Timestamp:   time.Now(),
					Evidence:    "process environment scan",
				})
				break
			}
		}
	}

	return findings
}

// scanLoadedLibs checks for suspicious loaded libraries
func (s *Scanner) scanLoadedLibs() []Finding {
	var findings []Finding

	// Check /proc/self/maps for suspicious library loads
	cmd := exec.Command("ldd", "/proc/self/exe")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Not critical if ldd fails
		return findings
	}

	// Look for signs of library hijacking (libraries in /tmp, user-writable directories)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "/tmp/") || strings.Contains(line, "/home/") {
			findings = append(findings, Finding{
				Type:        "LIBRARY_HIJACK_RISK",
				Description: "Library loaded from user-writable directory",
				Timestamp:   time.Now(),
				Evidence:    line,
			})
		}
	}

	return findings
}
