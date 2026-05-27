// Package report provides output formatting for diagnostic results.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/p2well/vdi-diag/internal/checker"
)

// Render outputs results in the specified format.
func Render(results []*checker.Result, format string, w io.Writer) error {
	switch strings.ToLower(format) {
	case "json":
		return renderJSON(results, w)
	case "html":
		return renderHTML(results, w)
	default:
		return renderText(results, w)
	}
}

func renderText(results []*checker.Result, w io.Writer) error {
	passed, failed, warnings := 0, 0, 0

	fmt.Fprintf(w, "╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(w, "║           VDI CONNECTIVITY DIAGNOSTIC REPORT                ║\n")
	fmt.Fprintf(w, "║         %s                          ║\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "╠══════════════════════════════════════════════════════════════╣\n")

	for _, r := range results {
		icon := statusIcon(r.Status)
		sevLabel := ""
		if r.Status == checker.StatusFail {
			sevLabel = fmt.Sprintf(" [%s]", r.Severity)
		}

		fmt.Fprintf(w, "║ %s %-20s %s%s\n", icon, r.Name, r.Message, sevLabel)

		if r.Details != "" {
			for _, line := range strings.Split(r.Details, "\n") {
				if line = strings.TrimSpace(line); line != "" {
					fmt.Fprintf(w, "║   └─ %s\n", line)
				}
			}
		}

		switch r.Status {
		case checker.StatusPass:
			passed++
		case checker.StatusFail:
			if r.Severity == checker.SeverityWarning {
				warnings++
			} else {
				failed++
			}
		}
	}

	fmt.Fprintf(w, "╠══════════════════════════════════════════════════════════════╣\n")
	fmt.Fprintf(w, "║ SUMMARY: %d passed, %d failed, %d warnings                  ║\n", passed, failed, warnings)
	fmt.Fprintf(w, "╚══════════════════════════════════════════════════════════════╝\n")

	if failed > 0 {
		fmt.Fprintf(w, "\n⚠️  CRITICAL ISSUES FOUND - These likely cause ICA session failures:\n")
		for _, r := range results {
			if r.Status == checker.StatusFail && r.Severity == checker.SeverityCritical {
				fmt.Fprintf(w, "  • %s: %s\n", r.Name, r.Message)
			}
		}
	}

	return nil
}

func renderJSON(results []*checker.Result, w io.Writer) error {
	type jsonReport struct {
		Timestamp string           `json:"timestamp"`
		Results   []*checker.Result `json:"results"`
		Summary   struct {
			Total    int `json:"total"`
			Passed   int `json:"passed"`
			Failed   int `json:"failed"`
			Warnings int `json:"warnings"`
		} `json:"summary"`
	}

	report := jsonReport{
		Timestamp: time.Now().Format(time.RFC3339),
		Results:   results,
	}
	report.Summary.Total = len(results)
	for _, r := range results {
		switch r.Status {
		case checker.StatusPass:
			report.Summary.Passed++
		case checker.StatusFail:
			report.Summary.Failed++
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func renderHTML(results []*checker.Result, w io.Writer) error {
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>VDI Diagnostic Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; background: #f5f5f5; }
.report { background: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
.check { padding: 12px; margin: 8px 0; border-radius: 4px; border-left: 4px solid; }
.pass { border-color: #28a745; background: #f0fff0; }
.fail { border-color: #dc3545; background: #fff0f0; }
.warn { border-color: #ffc107; background: #fffbf0; }
.name { font-weight: bold; }
.details { font-size: 0.85em; color: #666; margin-top: 4px; }
.summary { margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 4px; }
.timestamp { color: #888; font-size: 0.85em; }
</style>
</head>
<body>
<div class="report">
<h1>VDI Connectivity Diagnostic Report</h1>
<p class="timestamp">Generated: %s</p>
`, time.Now().Format("2006-01-02 15:04:05"))

	for _, r := range results {
		class := "pass"
		if r.Status == checker.StatusFail {
			class = "fail"
			if r.Severity == checker.SeverityWarning {
				class = "warn"
			}
		}

		fmt.Fprintf(w, `<div class="check %s">
<span class="name">%s %s</span>: %s
`, class, statusIcon(r.Status), r.Name, r.Message)
		if r.Details != "" {
			fmt.Fprintf(w, `<div class="details">%s</div>`, r.Details)
		}
		fmt.Fprintf(w, "</div>\n")
	}

	passed, failed := 0, 0
	for _, r := range results {
		if r.Status == checker.StatusPass {
			passed++
		} else {
			failed++
		}
	}

	fmt.Fprintf(w, `<div class="summary"><strong>Summary:</strong> %d passed, %d failed out of %d checks</div>
</div></body></html>`, passed, failed, len(results))

	return nil
}

func statusIcon(s checker.Status) string {
	switch s {
	case checker.StatusPass:
		return "✅"
	case checker.StatusFail:
		return "❌"
	case checker.StatusSkipped:
		return "⏭️"
	default:
		return "❓"
	}
}
