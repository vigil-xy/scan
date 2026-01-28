package teams

import (
	"testing"
)

func TestTeamsServiceCreation(t *testing.T) {
	service := NewTeamsService()
	if service == nil {
		t.Error("Failed to create TeamsService")
	}
}

func TestOrganizationCreation(t *testing.T) {
	service := NewTeamsService()

	org, err := service.CreateOrganization("Test Org", "admin@test.com", "pro")
	if err != nil {
		t.Fatalf("CreateOrganization failed: %v", err)
	}

	if org == nil {
		t.Error("Organization is nil")
	}

	if org.Name != "Test Org" {
		t.Errorf("Expected name 'Test Org', got %s", org.Name)
	}

	if org.Email != "admin@test.com" {
		t.Errorf("Expected email 'admin@test.com', got %s", org.Email)
	}

	if org.APIKey == "" {
		t.Error("Expected API key to be generated")
	}
}

func TestGetOrganization(t *testing.T) {
	service := NewTeamsService()

	org, _ := service.CreateOrganization("Get Test", "admin@test.com", "free")

	retrieved, err := service.GetOrganization(org.ID)
	if err != nil {
		t.Fatalf("GetOrganization failed: %v", err)
	}

	if retrieved.ID != org.ID {
		t.Errorf("Expected org ID %s, got %s", org.ID, retrieved.ID)
	}
}

func TestOrganizationNotFound(t *testing.T) {
	service := NewTeamsService()

	_, err := service.GetOrganization("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent org")
	}
}
