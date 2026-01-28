package telemetry

import (
	"sync"
	"time"
)

// Metrics tracks security events for telemetry
type Metrics struct {
	mu                    sync.RWMutex
	StartTime             time.Time
	SecretsDetected       int64
	ProcessesKilled       int64
	PortsBlocked          int64
	AlertsSent            int64
	ScansDone             int64
	AverageScanDuration   time.Duration
	TotalRuntime          time.Duration
	LastThreatTime        time.Time
	ThreatsByType         map[string]int64
	AlertsByChannel       map[string]int64
}

// NewMetrics creates a new metrics collector
func NewMetrics() *Metrics {
	return &Metrics{
		StartTime:       time.Now(),
		ThreatsByType:   make(map[string]int64),
		AlertsByChannel: make(map[string]int64),
	}
}

// RecordSecretDetection increments secret detection count
func (m *Metrics) RecordSecretDetection(secretType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SecretsDetected++
	m.ThreatsByType[secretType]++
	m.LastThreatTime = time.Now()
}

// RecordProcessKilled increments process kill count
func (m *Metrics) RecordProcessKilled() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ProcessesKilled++
	m.LastThreatTime = time.Now()
}

// RecordPortBlocked increments port block count
func (m *Metrics) RecordPortBlocked() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PortsBlocked++
	m.LastThreatTime = time.Now()
}

// RecordAlertSent increments alert count
func (m *Metrics) RecordAlertSent(channel string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AlertsSent++
	m.AlertsByChannel[channel]++
}

// RecordScan logs a completed scan
func (m *Metrics) RecordScan(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ScansDone++
	if m.AverageScanDuration == 0 {
		m.AverageScanDuration = duration
	} else {
		// Exponential moving average
		m.AverageScanDuration = (m.AverageScanDuration*9 + duration) / 10
	}
}

// GetStats returns current metrics snapshot
func (m *Metrics) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	runtime := time.Since(m.StartTime)
	return map[string]interface{}{
		"uptime_seconds":              int64(runtime.Seconds()),
		"total_scans":                 m.ScansDone,
		"average_scan_duration_ms":    int64(m.AverageScanDuration.Milliseconds()),
		"secrets_detected":            m.SecretsDetected,
		"processes_killed":            m.ProcessesKilled,
		"ports_blocked":               m.PortsBlocked,
		"alerts_sent":                 m.AlertsSent,
		"threats_by_type":             m.ThreatsByType,
		"alerts_by_channel":           m.AlertsByChannel,
		"seconds_since_last_threat":   int64(time.Since(m.LastThreatTime).Seconds()),
	}
}

// GetJSON returns metrics as JSON-serializable map
func (m *Metrics) GetJSON() map[string]interface{} {
	return m.GetStats()
}

// Reset clears all metrics
func (m *Metrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.StartTime = time.Now()
	m.SecretsDetected = 0
	m.ProcessesKilled = 0
	m.PortsBlocked = 0
	m.AlertsSent = 0
	m.ScansDone = 0
	m.ThreatsByType = make(map[string]int64)
	m.AlertsByChannel = make(map[string]int64)
}
