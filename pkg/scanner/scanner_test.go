package scanner

import (
	"context"
	"testing"
)

func TestScannerSecretsDetection(t *testing.T) {
	s := NewScanner()
	ctx := context.Background()

	// Test that scanner creates patterns
	if len(s.secretPatterns) == 0 {
		t.Error("No secret patterns initialized")
	}

	// Test that scanner creates port blacklist
	if len(s.blacklistPorts) == 0 {
		t.Error("No blacklist ports initialized")
	}

	// Test scan runs without panic
	findings := s.Scan(ctx)
	if findings == nil {
		t.Error("Scan returned nil instead of slice")
	}
}

func TestSecretPatterns(t *testing.T) {
	s := NewScanner()

	tests := []struct {
		input      string
		shouldFind bool
	}{
		{"AKIA1234567890123456", true},  // AWS key (AKIA + 16 alphanumeric)
		{"AKIAIOSFODNN7EXAMPLE", true}, // Another AWS key format
		{"notasecret", false},
		{"regular_var=value", false},
		{"Authorization: Bearer abc123def456", true}, // Bearer token
		{"api_key=super_secret_token_value", true}, // API key pattern
	}

	for _, test := range tests {
		found := false
		for _, pattern := range s.secretPatterns {
			if pattern.MatchString(test.input) {
				found = true
				break
			}
		}

		if found != test.shouldFind {
			t.Errorf("Pattern matching failed for %q: expected %v, got %v",
				test.input, test.shouldFind, found)
		}
	}
}

func TestPortBlacklist(t *testing.T) {
	s := NewScanner()

	expectedPorts := map[int]string{
		11434: "Ollama (prompt injection risk)",
		8000:  "Common service hijack vector",
		5000:  "Flask debug (if exposed)",
	}

	for port, reason := range expectedPorts {
		if actual, exists := s.blacklistPorts[port]; !exists {
			t.Errorf("Port %d not in blacklist", port)
		} else if actual != reason {
			t.Errorf("Port %d reason mismatch: expected %q, got %q", port, reason, actual)
		}
	}
}

func TestScanTimeout(t *testing.T) {
	s := NewScanner()
	ctx := context.Background()

	// Scan should complete without hanging
	findings := s.Scan(ctx)
	if findings == nil {
		t.Error("Scan returned nil")
	}
}
