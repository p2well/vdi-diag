package cmd

import (
	"fmt"
	"os"

	"github.com/p2well/vdi-diag/internal/checker"
	"github.com/p2well/vdi-diag/internal/report"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a report from diagnostic results",
	Long: `Reads saved diagnostic data and generates a formatted report.
Supports text, JSON, and HTML output formats.`,
	RunE: runReport,
}

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().StringP("format", "f", "text", "output format: text, json, html")
	reportCmd.Flags().StringP("output-file", "o", "", "write report to file (default: stdout)")
}

func runReport(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	outputFile, _ := cmd.Flags().GetString("output-file")

	// For now, run a fresh diagnosis and output as report.
	// Future: read from log file or saved results.
	fmt.Fprintln(os.Stderr, "Note: Run 'vdi-diag diagnose' with --output flag for direct report generation.")
	fmt.Fprintln(os.Stderr, "The 'report' command will support log-file analysis in a future version.")

	// Produce a sample empty report to demonstrate the format.
	results := []*checker.Result{}

	w := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	return report.Render(results, format, w)
}
