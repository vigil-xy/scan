package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/vigil-sec/vigil/pkg/teams"
)

// APIServer provides REST endpoints for Vigil Teams
type APIServer struct {
	teamsService *teams.TeamsService
	port         string
}

// NewAPIServer creates a new API server
func NewAPIServer(port string) *APIServer {
	return &APIServer{
		teamsService: teams.NewTeamsService(),
		port:         port,
	}
}

// Start begins listening for API requests
func (s *APIServer) Start() error {
	// Organization endpoints
	http.HandleFunc("/api/v1/organizations", s.handleOrganizations)
	http.HandleFunc("/api/v1/organizations/", s.handleOrganization)
	http.HandleFunc("/api/v1/members", s.handleMembers)
	http.HandleFunc("/api/v1/scans", s.handleScans)
	http.HandleFunc("/api/v1/dashboard", s.handleDashboard)

	// Health check
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	fmt.Printf("[API] Server starting on :%s\n", s.port)
	return http.ListenAndServe(":"+s.port, nil)
}

// handleOrganizations handles POST for new org, GET for listing
func (s *APIServer) handleOrganizations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "POST" {
		var req struct {
			Name  string `json:"name"`
			Email string `json:"email"`
			Plan  string `json:"plan"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		org, err := s.teamsService.CreateOrganization(req.Name, req.Email, req.Plan)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(org)
	} else if r.Method == "GET" {
		// In production: implement pagination
		json.NewEncoder(w).Encode(map[string]string{"message": "List organizations"})
	}
}

// handleOrganization retrieves specific org
func (s *APIServer) handleOrganization(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	orgID := r.URL.Path[len("/api/v1/organizations/"):]

	org, err := s.teamsService.GetOrganization(orgID)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(org)
}

// handleMembers manages team members
func (s *APIServer) handleMembers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		http.Error(w, "Missing org_id", http.StatusBadRequest)
		return
	}

	if r.Method == "POST" {
		var req struct {
			Email string `json:"email"`
			Name  string `json:"name"`
			Role  string `json:"role"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		member, err := s.teamsService.AddMember(orgID, req.Email, req.Name, req.Role)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(member)
	} else if r.Method == "GET" {
		members, err := s.teamsService.GetMembers(orgID)
		if err != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(members)
	}
}

// handleScans records and retrieves scans
func (s *APIServer) handleScans(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		http.Error(w, "Missing org_id", http.StatusBadRequest)
		return
	}

	if r.Method == "POST" {
		var req struct {
			Host     string         `json:"host"`
			Findings map[string]int `json:"findings"`
			Duration int            `json:"duration_ms"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		scan, err := s.teamsService.RecordScan(orgID, req.Host, req.Findings, req.Duration)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(scan)
	} else if r.Method == "GET" {
		scans, err := s.teamsService.GetScans(orgID, 100)
		if err != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(scans)
	}
}

// handleDashboard returns aggregated metrics
func (s *APIServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		http.Error(w, "Missing org_id", http.StatusBadRequest)
		return
	}

	dashboard, err := s.teamsService.GetDashboard(orgID)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(dashboard)
}
