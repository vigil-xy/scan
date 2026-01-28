package enforcer

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"syscall"

	"github.com/vigil-sec/vigil/pkg/scanner"
)

// Enforcer handles killing rogue processes and network blocks
type Enforcer struct {
	dryRun bool
}

// NewEnforcer creates a new enforcer
func NewEnforcer(dryRun bool) *Enforcer {
	return &Enforcer{dryRun: dryRun}
}

// Enforce takes action on detected threats
func (e *Enforcer) Enforce(ctx context.Context, findings []scanner.Finding) {
	for _, f := range findings {
		switch f.Type {
		case "EXPOSED_SECRET", "EXPOSED_SECRET_PROCESS":
			e.killProcess(f)
		case "HIJACKED_PORT":
			e.blockPort(f)
		}
	}
}

// killProcess terminates a process with exposed secrets
func (e *Enforcer) killProcess(f scanner.Finding) {
	if f.PID <= 0 {
		return
	}

	if e.dryRun {
		fmt.Printf("[DRY-RUN] Would kill PID %d (%s)\n", f.PID, f.Description)
		return
	}

	fmt.Printf("[ENFORCE] Killing PID %d: %s\n", f.PID, f.Description)
	if err := syscall.Kill(f.PID, syscall.SIGKILL); err != nil {
		log.Printf("Failed to kill PID %d: %v", f.PID, err)
	}
}

// blockPort uses iptables to block suspicious ports
func (e *Enforcer) blockPort(f scanner.Finding) {
	if e.dryRun {
		fmt.Printf("[DRY-RUN] Would block: %s\n", f.Description)
		return
	}

	fmt.Printf("[ENFORCE] Blocking port: %s\n", f.Description)

	// This is a simplified version - in production would parse port from evidence
	// and use: iptables -A INPUT -p tcp --dport PORT -j DROP
	cmd := exec.Command("sudo", "iptables", "-A", "INPUT", "-p", "tcp", "-j", "DROP", "-m", "comment", "--comment", f.Evidence)
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to block port: %v", err)
	}
}
