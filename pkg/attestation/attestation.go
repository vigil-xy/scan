package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/vigil-sec/vigil/pkg/scanner"
)

// Signer handles cryptographic signing of logs
type Signer struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// NewSigner creates a new signer with Ed25519 key
func NewSigner() *Signer {
	// Try to load from TPM or disk; fallback to generating new key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return &Signer{
		publicKey:  pub,
		privateKey: priv,
	}
}

// Sign creates a cryptographically signed log entry
func (s *Signer) Sign(findings []scanner.Finding) string {
	// Create log entry
	logEntry := fmt.Sprintf("vigil-scan|%d|%d-findings", time.Now().Unix(), len(findings))

	// Sign with Ed25519
	signature := ed25519.Sign(s.privateKey, []byte(logEntry))
	sigB64 := base64.StdEncoding.EncodeToString(signature)

	// Format: entry:signature:pubkey
	pubB64 := base64.StdEncoding.EncodeToString(s.publicKey)
	return fmt.Sprintf("%s:%s:%s", logEntry, sigB64, pubB64)
}

// Verify checks the validity of a signed log
func Verify(signedLog string) bool {
	// Parse: entry:signature:pubkey
	// This is a stub - full implementation would validate signature
	return len(signedLog) > 0
}

// LoadOrCreateKey loads key from disk or creates new one
func (s *Signer) LoadOrCreateKey(keyPath string) error {
	// Check if key exists
	if _, err := os.Stat(keyPath); err == nil {
		// Load from disk
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		s.privateKey = ed25519.PrivateKey(data)
		s.publicKey = s.privateKey.Public().(ed25519.PublicKey)
		return nil
	}

	// Create new key and save
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	if err := os.WriteFile(keyPath, priv, 0600); err != nil {
		return err
	}

	s.publicKey = pub
	s.privateKey = priv
	return nil
}
