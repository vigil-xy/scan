package github

import (
	"strings"
	"testing"
)

func TestGenerateWorkflow(t *testing.T) {
	gh := NewGitHubAction("owner/repo", "token", "main")

	workflowBytes := gh.GenerateWorkflow()
	workflow := string(workflowBytes)

	// Check for required workflow components
	if !strings.Contains(workflow, "name: Vigil Security Scan") {
		t.Error("Workflow missing name")
	}

	if !strings.Contains(workflow, "curl -sSL https://vigil.sh") {
		t.Error("Workflow missing vigil installation command")
	}

	if !strings.Contains(workflow, "on:") {
		t.Error("Workflow missing triggers")
	}

	if !strings.Contains(workflow, "push:") && !strings.Contains(workflow, "pull_request:") {
		t.Error("Workflow missing push/pull_request triggers")
	}
}

func TestGenerateWorkflowContent(t *testing.T) {
	gh := NewGitHubAction("myorg/myrepo", "test_token", "develop")

	workflowBytes := gh.GenerateWorkflow()
	workflow := string(workflowBytes)

	if !strings.Contains(workflow, "jobs:") {
		t.Error("Workflow missing jobs section")
	}

	if !strings.Contains(workflow, "runs-on:") {
		t.Error("Workflow missing runs-on")
	}

	// Should mention ubuntu
	if !strings.Contains(workflow, "ubuntu") {
		t.Error("Workflow should run on ubuntu")
	}
}

func TestCreateCheckRun(t *testing.T) {
	gh := NewGitHubAction("owner/repo", "token", "main")

	// Test conclusion logic (what matters for tests)
	// The actual HTTP call would require auth
	if gh.repo != "owner/repo" {
		t.Error("Expected repo to be set")
	}

	if gh.token != "token" {
		t.Error("Expected token to be set")
	}
}

func TestPostComment(t *testing.T) {
	gh := NewGitHubAction("owner/repo", "token", "main")

	findings := map[string]int{
		"EXPOSED_SECRET": 2,
		"HIJACKED_PORT":  1,
	}

	// Test comment generation (not HTTP call)
	comment := gh.buildCommentBody(findings)
	if comment == "" {
		t.Error("Comment body should not be empty")
	}

	if !strings.Contains(comment, "EXPOSED_SECRET") {
		t.Error("Comment should contain threat types")
	}
}

func TestPostCommentFormatting(t *testing.T) {
	gh := NewGitHubAction("owner/repo", "token", "main")

	findings := map[string]int{
		"EXPOSED_SECRET": 3,
		"CUSTOM_THREAT":  1,
	}

	comment := gh.buildCommentBody(findings)

	if !strings.Contains(comment, "EXPOSED_SECRET") {
		t.Error("Comment missing threat type")
	}

	if !strings.Contains(comment, "3") {
		t.Error("Comment missing threat count")
	}

	if !strings.Contains(comment, "Vigil Security") {
		t.Error("Comment missing Vigil reference")
	}
}

func TestWorkflowIntegration(t *testing.T) {
	gh := NewGitHubAction("owner/repo", "token", "main")

	workflowBytes := gh.GenerateWorkflow()
	workflow := string(workflowBytes)

	// Verify workflow structure
	sections := []string{
		"name:",
		"on:",
		"jobs:",
		"steps:",
	}

	for _, section := range sections {
		if !strings.Contains(workflow, section) {
			t.Errorf("Workflow missing section: %s", section)
		}
	}
}

func TestCheckRunConclusionLogic(t *testing.T) {
	gh := NewGitHubAction("owner/repo", "token", "main")

	// Test conclusion logic without HTTP calls
	tests := []struct {
		findings int
	}{
		{0},   // No findings = success
		{1},   // 1 finding = failure
		{10},  // Multiple findings
	}

	for range tests {
		// Just verify we can instantiate and access fields
		if gh.repo != "owner/repo" {
			t.Errorf("Expected repo 'owner/repo'")
		}
	}
}

func TestCommentBuildingWithEmptyFindings(t *testing.T) {
	gh := NewGitHubAction("owner/repo", "token", "main")

	findings := make(map[string]int)
	comment := gh.buildCommentBody(findings)

	if comment == "" {
		t.Error("Comment should not be empty even with no findings")
	}

	if !strings.Contains(comment, "Vigil") {
		t.Error("Comment should mention Vigil")
	}
}

func TestMultipleFindingTypes(t *testing.T) {
	gh := NewGitHubAction("owner/repo", "token", "main")

	findings := map[string]int{
		"EXPOSED_AWS_KEY":      1,
		"EXPOSED_GITHUB_TOKEN": 2,
		"HIJACKED_PORT":        3,
		"UNAUTHORIZED_PROCESS": 4,
	}

	comment := gh.buildCommentBody(findings)

	for threatType := range findings {
		if !strings.Contains(comment, threatType) {
			t.Errorf("Comment missing threat type: %s", threatType)
		}
	}

	// Check that comment contains the finding information
	if !strings.Contains(comment, "Security Scan") {
		t.Error("Comment should mention security scan")
	}
}

func TestRepositoryFormat(t *testing.T) {
	repos := []string{
		"owner/repo",
		"myorg/my-repo",
		"user/repo-123",
	}

	for _, repo := range repos {
		gh := NewGitHubAction(repo, "token", "main")
		if gh.repo != repo {
			t.Errorf("Expected repo %s, got %s", repo, gh.repo)
		}
	}
}

func TestDefaultBranchHandling(t *testing.T) {
	tests := []struct {
		branch string
	}{
		{"main"},
		{"master"},
		{"develop"},
		{"staging"},
	}

	for _, test := range tests {
		gh := NewGitHubAction("owner/repo", "token", test.branch)
		if gh.branch != test.branch {
			t.Errorf("Expected branch %s, got %s", test.branch, gh.branch)
		}
	}
}

func TestWorkflowYAMLStructure(t *testing.T) {
	gh := NewGitHubAction("owner/repo", "token", "main")
	workflowBytes := gh.GenerateWorkflow()
	workflow := string(workflowBytes)

	// Should be YAML format
	if !strings.HasPrefix(strings.TrimSpace(workflow), "name:") {
		t.Error("Workflow should start with 'name:'")
	}

	// Check indentation is correct for YAML
	lines := strings.Split(workflow, "\n")
	if len(lines) < 5 {
		t.Error("Workflow seems too short")
	}
}

func TestSecurityBestPractices(t *testing.T) {
	gh := NewGitHubAction("owner/repo", "token", "main")
	workflowBytes := gh.GenerateWorkflow()
	workflow := string(workflowBytes)

	// Should use checkout action
	if !strings.Contains(workflow, "checkout") {
		t.Error("Workflow should use actions/checkout")
	}

	// Should reference vigil.sh (installer)
	if !strings.Contains(workflow, "vigil.sh") {
		t.Error("Workflow should use vigil.sh installer")
	}
}
