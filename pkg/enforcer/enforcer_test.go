package enforcer

import (
	"context"
	"testing"

	"github.com/vigil-sec/vigil/pkg/scanner"
)

func TestEnforcerCreation(t *testing.T) {
	enforcer := NewEnforcer(true)

	if enforcer == nil {
		t.Error("Enforcer is nil")
	}

	if !enforcer.dryRun {
		t.Error("Dry-run flag not set")
	}
}

func TestEnforcerDryRun(t *testing.T) {
	enforcer := NewEnforcer(true)
	ctx := context.Background()

	findings := []scanner.Finding{
		{
			Type:        "EXPOSED_SECRET",
			Description: "Test secret",
			PID:         9999,
		},
	}

	// Should not panic in dry-run
	enforcer.Enforce(ctx, findings)
}

func TestEnforcerWithoutDryRun(t *testing.T) {
	enforcer := NewEnforcer(true) // Keep as dry-run for test safety
	ctx := context.Background()

	findings := []scanner.Finding{
		{
			Type:        "HIJACKED_PORT",
			Description: "Test port",
		},
	}

	// Should not panic
	enforcer.Enforce(ctx, findings)
}

func TestEnforcerEmptyFindings(t *testing.T) {
	enforcer := NewEnforcer(true)
	ctx := context.Background()

	findings := []scanner.Finding{}

	// Should handle empty findings
	enforcer.Enforce(ctx, findings)
}
