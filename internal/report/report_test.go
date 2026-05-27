package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/p2well/vdi-diag/internal/checker"
)

func sampleResults() []*checker.Result {
	return []*checker.Result{
		{
			Name:     "DNS Resolution",
			Status:   checker.StatusPass,
			Severity: checker.SeverityCritical,
			Message:  "Resolved example.com to 93.184.216.34 in 15ms",
			Duration: 15 * time.Millisecond,
		},
		{
			Name:     "TCP Port 443",
			Status:   checker.StatusFail,
			Severity: checker.SeverityCritical,
			Message:  "Cannot connect to example.com:443",
			Details:  "connection timed out",
			Duration: 5 * time.Second,
		},
		{
			Name:     "Proxy Detection",
			Status:   checker.StatusPass,
			Severity: checker.SeverityWarning,
			Message:  "No proxy configured",
			Duration: 100 * time.Millisecond,
		},
	}
}

func TestRenderText(t *testing.T) {
	var buf bytes.Buffer
	results := sampleResults()

	err := Render(results, "text", &buf)
	if err != nil {
		t.Fatalf("Render(text) error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "VDI CONNECTIVITY DIAGNOSTIC REPORT") {
		t.Error("text output missing report header")
	}
	if !strings.Contains(output, "DNS Resolution") {
		t.Error("text output missing DNS check")
	}
	if !strings.Contains(output, "SUMMARY") {
		t.Error("text output missing summary")
	}
}

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	results := sampleResults()

	err := Render(results, "json", &buf)
	if err != nil {
		t.Fatalf("Render(json) error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v", err)
	}

	if _, ok := parsed["results"]; !ok {
		t.Error("JSON output missing 'results' field")
	}
	if _, ok := parsed["summary"]; !ok {
		t.Error("JSON output missing 'summary' field")
	}
	if _, ok := parsed["timestamp"]; !ok {
		t.Error("JSON output missing 'timestamp' field")
	}
}

func TestRenderHTML(t *testing.T) {
	var buf bytes.Buffer
	results := sampleResults()

	err := Render(results, "html", &buf)
	if err != nil {
		t.Fatalf("Render(html) error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("HTML output missing doctype")
	}
	if !strings.Contains(output, "VDI Connectivity Diagnostic Report") {
		t.Error("HTML output missing title")
	}
	if !strings.Contains(output, "DNS Resolution") {
		t.Error("HTML output missing check result")
	}
}
