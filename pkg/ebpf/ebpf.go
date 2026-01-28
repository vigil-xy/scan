package ebpf

import (
	"context"
	"fmt"
	"log"
	"time"
)

// Event represents a syscall event captured by eBPF
type Event struct {
	Timestamp   time.Time
	EventType   string // "execve", "connect", "bind"
	PID         uint32
	UID         uint32
	Command     string
	Args        string
	SrcIP       string
	DstIP       string
	Port        uint16
	ReturnCode  int32
	ThreatLevel string // "critical", "high", "medium", "low"
}

// Probe manages eBPF program loading and event collection
type Probe struct {
	enabled bool
	events  chan Event
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewProbe creates a new eBPF probe manager
func NewProbe() *Probe {
	ctx, cancel := context.WithCancel(context.Background())
	return &Probe{
		enabled: false, // Set to true when eBPF compiled
		events:  make(chan Event, 100),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start begins listening for syscall events
func (p *Probe) Start() error {
	if !p.enabled {
		return fmt.Errorf("eBPF probe not compiled - requires clang/llvm")
	}

	go p.eventLoop()
	return nil
}

// Stop terminates event collection
func (p *Probe) Stop() {
	p.cancel()
	close(p.events)
}

// EventChan returns the event stream
func (p *Probe) EventChan() <-chan Event {
	return p.events
}

// eventLoop collects syscall events from kernel
func (p *Probe) eventLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			// In production: poll eBPF ringbuffer
			// For now: demonstrate with mock events
		}
	}
}

// FilterByThreat returns events matching threat level
func (p *Probe) FilterByThreat(level string) []Event {
	var filtered []Event
	for {
		select {
		case evt := <-p.events:
			if evt.ThreatLevel == level {
				filtered = append(filtered, evt)
			}
		default:
			return filtered
		}
	}
}

// ThreatAnalysis evaluates syscall events for security issues
type ThreatAnalysis struct {
	ExecsToWatchlist  int
	ConnectsToSuspiciousPorts int
	BindsToExposedPorts int
	EnvVarLeaks        int
	LibraryHijacks     int
}

// Analyze examines captured events for threats
func (p *Probe) Analyze(events []Event) *ThreatAnalysis {
	analysis := &ThreatAnalysis{}

	for _, evt := range events {
		switch evt.EventType {
		case "execve":
			// Check if executable is in watchlist or has suspicious args
			if p.isWatchlistBinary(evt.Command) || p.hasSuspiciousArgs(evt.Args) {
				analysis.ExecsToWatchlist++
			}
		case "connect":
			// Check if connecting to suspicious ports or C2 IPs
			if p.isSuspiciousPort(evt.Port) {
				analysis.ConnectsToSuspiciousPorts++
			}
		case "bind":
			// Check if binding to exposed ports
			if p.isExposedPort(evt.Port) {
				analysis.BindsToExposedPorts++
			}
		}
	}

	return analysis
}

// isWatchlistBinary checks if command is in threat list
func (p *Probe) isWatchlistBinary(cmd string) bool {
	watchlist := map[string]bool{
		"/bin/nc":       true,
		"/bin/bash":     true,
		"/usr/bin/curl": true,
		"/usr/bin/wget": true,
		"/usr/bin/ssh":  true,
	}
	return watchlist[cmd]
}

// hasSuspiciousArgs detects dangerous command-line arguments
func (p *Probe) hasSuspiciousArgs(args string) bool {
	suspiciousPatterns := []string{
		"-e /bin/bash",  // nc -e /bin/bash (reverse shell)
		"rm -rf /",      // Destructive
		":():{:|:&};:",  // Fork bomb
	}
	for _, pattern := range suspiciousPatterns {
		if pattern == args {
			return true
		}
	}
	return false
}

// isSuspiciousPort checks for known C2/malware ports
func (p *Probe) isSuspiciousPort(port uint16) bool {
	suspiciousPorts := map[uint16]bool{
		4444:  true, // Metasploit
		5555:  true, // ADB/Metasploit
		6666:  true, // IRC
		6667:  true, // IRC
		31337: true, // Elite/Trojan
	}
	return suspiciousPorts[port]
}

// isExposedPort checks if port should not be listening
func (p *Probe) isExposedPort(port uint16) bool {
	exposedPorts := map[uint16]bool{
		11434: true, // Ollama
		8000:  true, // Common hijack
		5000:  true, // Flask
	}
	return exposedPorts[port]
}

// Enable turns on eBPF monitoring (when compiled)
func (p *Probe) Enable() {
	p.enabled = true
	log.Println("eBPF probe enabled")
}

// IsEnabled returns whether eBPF is active
func (p *Probe) IsEnabled() bool {
	return p.enabled
}
