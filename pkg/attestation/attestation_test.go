package attestation

import (
	"crypto/ed25519"
	"testing"

	"github.com/vigil-sec/vigil/pkg/scanner"
)

func TestSignerCreation(t *testing.T) {
	signer := NewSigner()

	if signer.publicKey == nil {
		t.Error("Public key is nil")
	}

	if signer.privateKey == nil {
		t.Error("Private key is nil")
	}

	// Verify key sizes
	if len(signer.publicKey) != ed25519.PublicKeySize {
		t.Errorf("Public key size mismatch: expected %d, got %d",
			ed25519.PublicKeySize, len(signer.publicKey))
	}

	if len(signer.privateKey) != ed25519.PrivateKeySize {
		t.Errorf("Private key size mismatch: expected %d, got %d",
			ed25519.PrivateKeySize, len(signer.privateKey))
	}
}

func TestSigningAndVerification(t *testing.T) {
	signer := NewSigner()

	findings := []scanner.Finding{
		{
			Type:        "TEST_THREAT",
			Description: "Test finding",
			PID:         1234,
		},
	}

	signedLog := signer.Sign(findings)

	if signedLog == "" {
		t.Error("Signed log is empty")
	}

	// Check format: entry:signature:pubkey
	if len(signedLog) < 10 {
		t.Errorf("Signed log too short: %d chars", len(signedLog))
	}

	// Should contain colons
	if count := len([]rune(signedLog)) - len("vigil-scan|"); count < 3 {
		t.Error("Signed log missing expected separators")
	}
}

func TestMultipleFindings(t *testing.T) {
	signer := NewSigner()

	findings := []scanner.Finding{
		{Type: "THREAT1", Description: "First", PID: 100},
		{Type: "THREAT2", Description: "Second", PID: 200},
		{Type: "THREAT3", Description: "Third", PID: 300},
	}

	signedLog := signer.Sign(findings)
	if signedLog == "" {
		t.Error("Failed to sign multiple findings")
	}
}

func TestVerifyFunction(t *testing.T) {
	signer := NewSigner()
	findings := []scanner.Finding{
		{Type: "TEST", Description: "Test"},
	}

	signedLog := signer.Sign(findings)
	result := Verify(signedLog)

	if !result {
		t.Error("Verification failed")
	}

	if Verify("") {
		t.Error("Empty string should not verify")
	}
}
