package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// GitHubAction integrates Vigil with GitHub Actions
type GitHubAction struct {
	repo   string // owner/repo
	token  string // GitHub token
	branch string // Branch to scan
}

// NewGitHubAction creates a new GitHub Actions integration
func NewGitHubAction(repo, token, branch string) *GitHubAction {
	return &GitHubAction{
		repo:   repo,
		token:  token,
		branch: branch,
	}
}

// Workflow represents a GitHub Actions workflow definition
type Workflow struct {
	Name string `json:"name"`
	On   struct {
		Push struct {
			Branches []string `json:"branches"`
		} `json:"push"`
	} `json:"on"`
	Jobs struct {
		VigilScan struct {
			RunsOn string `json:"runs-on"`
			Steps  []struct {
				Uses string `json:"uses,omitempty"`
				Run  string `json:"run,omitempty"`
				Name string `json:"name"`
			} `json:"steps"`
		} `json:"vigil-scan"`
	} `json:"jobs"`
}

// GenerateWorkflow creates a GitHub Actions workflow file
func (g *GitHubAction) GenerateWorkflow() []byte {
	workflow := `name: Vigil Security Scan

on:
  push:
    branches:
      - main
      - develop
  pull_request:
    branches:
      - main

jobs:
  vigil-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Vigil Security Scanner
        run: |
          curl -sSL https://vigil.sh | sh -- --dry-run
      
      - name: Report Results
        if: always()
        run: |
          echo "Vigil security scan completed"
          echo "Review findings above for any threats"
      
      - name: Upload SARIF (Optional)
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: vigil-findings.sarif
          wait-for-processing: true
`
	return []byte(workflow)
}

// CreateCheckRun creates a GitHub check run for security scan
func (g *GitHubAction) CreateCheckRun(commitSHA string, status string, findings int) error {
	conclusion := "success"
	if findings > 0 {
		conclusion = "failure"
	}

	payload := map[string]interface{}{
		"name":       "Vigil Security Scan",
		"head_sha":   commitSHA,
		"status":     status,
		"conclusion": conclusion,
		"output": map[string]interface{}{
			"title":   "Vigil Security Scan Results",
			"summary": fmt.Sprintf("Found %d security issues", findings),
		},
	}

	data, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("https://api.github.com/repos/%s/check-runs", g.repo),
		bytes.NewReader(data))

	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create check run: %d", resp.StatusCode)
	}

	return nil
}

// PostComment posts scan results as PR comment
func (g *GitHubAction) PostComment(prNumber int, findings map[string]int) error {
	comment := "## 🔍 Vigil Security Scan\n\n"

	if len(findings) == 0 {
		comment += "✅ **No threats detected**\n"
	} else {
		comment += "⚠️ **Security Issues Found**\n\n"
		comment += "| Issue Type | Count |\n"
		comment += "|-----------|-------|\n"
		for threat, count := range findings {
			comment += fmt.Sprintf("| %s | %d |\n", threat, count)
		}
	}

	comment += "\n*Scanned with [Vigil Security Scanner](https://github.com/vigil-sec/vigil)*"

	payload := map[string]string{
		"body": comment,
	}

	data, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("https://api.github.com/repos/%s/issues/%d/comments", g.repo, prNumber),
		bytes.NewReader(data))

	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to post comment: %d", resp.StatusCode)
	}

	return nil
}

// buildCommentBody generates the comment body with findings summary
func (g *GitHubAction) buildCommentBody(findings map[string]int) string {
	if len(findings) == 0 {
		return "## ✅ Vigil Security Scan\n\nNo security issues detected!"
	}

	body := "## ⚠️ Vigil Security Scan Results\n\nFound the following security issues:\n\n"

	for threat, count := range findings {
		body += fmt.Sprintf("- **%s**: %d occurrence(s)\n", threat, count)
	}

	body += "\nPlease review and remediate before merging."
	return body
}

