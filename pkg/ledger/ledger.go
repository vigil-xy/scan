package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// LogEntry represents a single security event in the ledger
type LogEntry struct {
	Sequence      int64     // Entry number
	Timestamp     time.Time // When it occurred
	EventType     string    // EXPOSED_SECRET, PROCESS_KILLED, etc
	Description   string    // Human-readable description
	PID           int       // Process ID
	Evidence      string    // Proof/evidence
	Signature     string    // Ed25519 signature
	PreviousHash  string    // Hash of previous entry (blockchain-like)
	Hash          string    // Hash of this entry
	PublicKey     string    // Signer's public key
	Verified      bool      // Signature verified
}

// Ledger is an immutable log of all security events
type Ledger struct {
	mu      sync.RWMutex
	entries []LogEntry
	seq     int64
}

// NewLedger creates a new ledger
func NewLedger() *Ledger {
	return &Ledger{
		entries: make([]LogEntry, 0),
		seq:     0,
	}
}

// Append adds a new entry to the ledger
func (l *Ledger) Append(entry LogEntry) string {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	entry.Sequence = l.seq

	// Get previous hash
	if len(l.entries) > 0 {
		entry.PreviousHash = l.entries[len(l.entries)-1].Hash
	}

	// Calculate hash
	entry.Hash = l.calculateHash(entry)

	l.entries = append(l.entries, entry)
	return entry.Hash
}

// calculateHash creates SHA256 hash of entry
func (l *Ledger) calculateHash(entry LogEntry) string {
	data := fmt.Sprintf("%d|%s|%s|%s|%s|%s",
		entry.Sequence,
		entry.Timestamp.String(),
		entry.EventType,
		entry.Description,
		entry.PreviousHash,
		entry.Signature,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Get returns entry by sequence number
func (l *Ledger) Get(seq int64) (LogEntry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for _, entry := range l.entries {
		if entry.Sequence == seq {
			return entry, nil
		}
	}
	return LogEntry{}, fmt.Errorf("entry not found: %d", seq)
}

// GetAll returns all entries
func (l *Ledger) GetAll() []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Return copy
	entries := make([]LogEntry, len(l.entries))
	copy(entries, l.entries)
	return entries
}

// GetSince returns entries after timestamp
func (l *Ledger) GetSince(t time.Time) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var filtered []LogEntry
	for _, entry := range l.entries {
		if entry.Timestamp.After(t) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// GetByType returns entries of specific type
func (l *Ledger) GetByType(eventType string) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var filtered []LogEntry
	for _, entry := range l.entries {
		if entry.EventType == eventType {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// Count returns number of entries
func (l *Ledger) Count() int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return int64(len(l.entries))
}

// Verify checks integrity of ledger
func (l *Ledger) Verify() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for i, entry := range l.entries {
		// Verify hash
		expectedHash := l.calculateHash(entry)
		if expectedHash != entry.Hash {
			return false
		}

		// Verify chain continuity
		if i > 0 {
			if entry.PreviousHash != l.entries[i-1].Hash {
				return false
			}
		}
	}
	return true
}

// ExportJSON returns ledger as JSON-serializable structure
func (l *Ledger) ExportJSON() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return map[string]interface{}{
		"total_entries": len(l.entries),
		"verified":      l.verifyChain(),
		"entries":       l.entries,
	}
}

// verifyChain checks if chain is intact
func (l *Ledger) verifyChain() bool {
	for i := 1; i < len(l.entries); i++ {
		if l.entries[i].PreviousHash != l.entries[i-1].Hash {
			return false
		}
	}
	return true
}

// GetLatest returns most recent entry
func (l *Ledger) GetLatest() (LogEntry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if len(l.entries) == 0 {
		return LogEntry{}, fmt.Errorf("ledger is empty")
	}
	return l.entries[len(l.entries)-1], nil
}

// Summary returns statistics about ledger
func (l *Ledger) Summary() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()

	types := make(map[string]int)
	for _, entry := range l.entries {
		types[entry.EventType]++
	}

	return map[string]interface{}{
		"total_entries":   len(l.entries),
		"events_by_type":  types,
		"chain_verified":  l.verifyChain(),
		"first_entry":     l.getFirstTime(),
		"last_entry":      l.getLastTime(),
	}
}

func (l *Ledger) getFirstTime() time.Time {
	if len(l.entries) == 0 {
		return time.Time{}
	}
	return l.entries[0].Timestamp
}

func (l *Ledger) getLastTime() time.Time {
	if len(l.entries) == 0 {
		return time.Time{}
	}
	return l.entries[len(l.entries)-1].Timestamp
}
