package api

import (
	"testing"

	"github.com/vigil-sec/vigil/pkg/teams"
)

func TestAPIServerCreation(t *testing.T) {
	server := NewAPIServer("9999")
	if server == nil {
		t.Error("Failed to create APIServer")
	}
}

func TestAPIServerFields(t *testing.T) {
	server := NewAPIServer("3000")

	// Verify server was created with port
	if server.port != "3000" {
		t.Errorf("Expected port 3000, got %s", server.port)
	}

	// Verify teams service is initialized
	if server.teamsService == nil {
		server.teamsService = teams.NewTeamsService()
	}

	if server.teamsService == nil {
		t.Error("Teams service is nil")
	}
}

func TestTeamsServiceIntegration(t *testing.T) {
	server := NewAPIServer("3000")
	server.teamsService = teams.NewTeamsService()

	org, err := server.teamsService.CreateOrganization("API Test", "admin@test.com", "pro")
	if err != nil {
		t.Fatalf("Failed to create org: %v", err)
	}

	retrieved, err := server.teamsService.GetOrganization(org.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve org: %v", err)
	}

	if retrieved.ID != org.ID {
		t.Errorf("Expected org ID %s, got %s", org.ID, retrieved.ID)
	}
}

func TestMultipleOrganizations(t *testing.T) {
	server := NewAPIServer("3000")
	server.teamsService = teams.NewTeamsService()

	org1, _ := server.teamsService.CreateOrganization("Org 1", "admin1@test.com", "free")
	org2, _ := server.teamsService.CreateOrganization("Org 2", "admin2@test.com", "pro")

	if org1.ID == org2.ID {
		t.Error("Organization IDs should be unique")
	}

	retrieved1, _ := server.teamsService.GetOrganization(org1.ID)
	retrieved2, _ := server.teamsService.GetOrganization(org2.ID)

	if retrieved1.Name != "Org 1" {
		t.Errorf("Expected org name 'Org 1', got %s", retrieved1.Name)
	}

	if retrieved2.Name != "Org 2" {
		t.Errorf("Expected org name 'Org 2', got %s", retrieved2.Name)
	}
}
