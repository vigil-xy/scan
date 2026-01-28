package teams

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Organization represents a Vigil Teams customer
type Organization struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Plan        string    `json:"plan"` // "free", "pro", "enterprise"
	Members     int       `json:"members"`
	APIKey      string    `json:"api_key,omitempty"`
	Active      bool      `json:"active"`
}

// TeamMember represents a user in an organization
type TeamMember struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"org_id"`
	Email      string    `json:"email"`
	Name       string    `json:"name"`
	Role       string    `json:"role"` // "owner", "admin", "member"
	JoinedAt   time.Time `json:"joined_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

// Scan represents a security scan result
type Scan struct {
	ID          string            `json:"id"`
	OrgID       string            `json:"org_id"`
	Timestamp   time.Time         `json:"timestamp"`
	Host        string            `json:"host"`
	Findings    int               `json:"findings"`
	Threats     map[string]int    `json:"threats_by_type"`
	Status      string            `json:"status"` // "clean", "warning", "critical"
	Duration    int               `json:"duration_ms"`
}

// Dashboard represents aggregated security status
type Dashboard struct {
	OrgID           string
	TotalScans      int64
	TotalThreats    int64
	ThreatTrend     []int64 // Last 7 days
	MostActiveHosts []string
	LastScanTime    time.Time
}

// TeamsService manages organization and team features
type TeamsService struct {
	mu            sync.RWMutex
	organizations map[string]*Organization
	members       map[string][]TeamMember
	scans         map[string][]Scan
}

// NewTeamsService creates a new teams service
func NewTeamsService() *TeamsService {
	return &TeamsService{
		organizations: make(map[string]*Organization),
		members:       make(map[string][]TeamMember),
		scans:         make(map[string][]Scan),
	}
}

// CreateOrganization registers a new team
func (ts *TeamsService) CreateOrganization(name, email, plan string) (*Organization, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	id := generateID()
	apiKey := generateAPIKey()

	org := &Organization{
		ID:        id,
		Name:      name,
		Email:     email,
		Plan:      plan,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		APIKey:    apiKey,
		Active:    true,
		Members:   1,
	}

	ts.organizations[id] = org
	ts.members[id] = []TeamMember{
		{
			ID:       generateID(),
			OrgID:    id,
			Email:    email,
			Name:     "Owner",
			Role:     "owner",
			JoinedAt: time.Now(),
		},
	}
	ts.scans[id] = []Scan{}

	return org, nil
}

// AddMember adds a user to organization
func (ts *TeamsService) AddMember(orgID, email, name, role string) (*TeamMember, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if _, exists := ts.organizations[orgID]; !exists {
		return nil, errOrgNotFound
	}

	member := &TeamMember{
		ID:       generateID(),
		OrgID:    orgID,
		Email:    email,
		Name:     name,
		Role:     role,
		JoinedAt: time.Now(),
	}

	ts.members[orgID] = append(ts.members[orgID], *member)
	ts.organizations[orgID].Members++

	return member, nil
}

// RecordScan logs a security scan for organization
func (ts *TeamsService) RecordScan(orgID, host string, findings map[string]int, duration int) (*Scan, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if _, exists := ts.organizations[orgID]; !exists {
		return nil, errOrgNotFound
	}

	totalThreats := 0
	for _, count := range findings {
		totalThreats += count
	}

	status := "clean"
	if totalThreats > 0 {
		status = "warning"
	}
	if totalThreats > 10 {
		status = "critical"
	}

	scan := &Scan{
		ID:        generateID(),
		OrgID:     orgID,
		Timestamp: time.Now(),
		Host:      host,
		Findings:  totalThreats,
		Threats:   findings,
		Status:    status,
		Duration:  duration,
	}

	ts.scans[orgID] = append(ts.scans[orgID], *scan)
	return scan, nil
}

// GetDashboard returns aggregated security metrics
func (ts *TeamsService) GetDashboard(orgID string) (*Dashboard, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if _, exists := ts.organizations[orgID]; !exists {
		return nil, errOrgNotFound
	}

	scans := ts.scans[orgID]
	if len(scans) == 0 {
		return &Dashboard{
			OrgID:        orgID,
			TotalScans:   0,
			TotalThreats: 0,
			ThreatTrend:  make([]int64, 7),
		}, nil
	}

	dashboard := &Dashboard{
		OrgID:      orgID,
		TotalScans: int64(len(scans)),
	}

	// Calculate threat trend (last 7 days)
	now := time.Now()
	weekAgo := now.AddDate(0, 0, -7)

	threatsByDay := make([]int64, 7)
	hostThreatCounts := make(map[string]int)

	for _, scan := range scans {
		if scan.Timestamp.After(weekAgo) {
			dayIndex := int(now.Sub(scan.Timestamp).Hours() / 24)
			if dayIndex < 7 {
				threatsByDay[dayIndex] += int64(scan.Findings)
			}
			dashboard.TotalThreats += int64(scan.Findings)
			hostThreatCounts[scan.Host] += scan.Findings
		}

		if scan.Timestamp.After(dashboard.LastScanTime) {
			dashboard.LastScanTime = scan.Timestamp
		}
	}

	dashboard.ThreatTrend = threatsByDay

	// Get most active hosts
	for host := range hostThreatCounts {
		dashboard.MostActiveHosts = append(dashboard.MostActiveHosts, host)
	}

	return dashboard, nil
}

// GetOrganization retrieves organization details
func (ts *TeamsService) GetOrganization(orgID string) (*Organization, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	org, exists := ts.organizations[orgID]
	if !exists {
		return nil, errOrgNotFound
	}

	return org, nil
}

// GetMembers returns team members
func (ts *TeamsService) GetMembers(orgID string) ([]TeamMember, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if _, exists := ts.organizations[orgID]; !exists {
		return nil, errOrgNotFound
	}

	members := ts.members[orgID]
	result := make([]TeamMember, len(members))
	copy(result, members)
	return result, nil
}

// GetScans returns recent scans for organization
func (ts *TeamsService) GetScans(orgID string, limit int) ([]Scan, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if _, exists := ts.organizations[orgID]; !exists {
		return nil, errOrgNotFound
	}

	scans := ts.scans[orgID]
	if len(scans) > limit {
		scans = scans[len(scans)-limit:]
	}

	result := make([]Scan, len(scans))
	copy(result, scans)
	return result, nil
}

// recordScanWithTime records a scan with a specific timestamp (used for testing)
func (svc *TeamsService) recordScanWithTime(orgID, host string, findings map[string]int, duration int, timestamp time.Time) (*Scan, error) {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	_, exists := svc.organizations[orgID]
	if !exists {
		return nil, errOrgNotFound
	}

	// Calculate total findings
	totalFindings := 0
	for _, count := range findings {
		totalFindings += count
	}

	scan := &Scan{
		ID:        generateID(),
		OrgID:     orgID,
		Timestamp: timestamp,
		Host:      host,
		Findings:  totalFindings,
		Threats:   findings,
		Status:    "completed",
		Duration:  duration,
	}

	svc.scans[orgID] = append(svc.scans[orgID], *scan)
	return scan, nil
}

// Helper functions
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "vigil_" + hex.EncodeToString(b)
}

var (
	errOrgNotFound = errors.New("organization not found")
)
