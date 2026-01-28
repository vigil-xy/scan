package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleDashboard(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleDashboard)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "text/html" {
		t.Errorf("handler returned wrong content type: got %v want text/html", ct)
	}

	if len(rr.Body.String()) == 0 {
		t.Error("handler returned empty body")
	}
}

func TestHandleScan(t *testing.T) {
	req, err := http.NewRequest("GET", "/api/scan", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleScan)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("handler returned wrong content type: got %v want application/json", ct)
	}

	if len(rr.Body.String()) == 0 {
		t.Error("handler returned empty JSON response")
	}
}

func TestScanResult(t *testing.T) {
	result := ScanResult{
		Timestamp: "2026-01-28T00:00:00Z",
		Ports:     []string{"11434"},
		Secrets:   []string{},
		Processes: []string{},
	}

	if result.Timestamp == "" {
		t.Error("ScanResult timestamp is empty")
	}

	if len(result.Ports) != 1 {
		t.Errorf("ScanResult ports length: got %d want 1", len(result.Ports))
	}
}
