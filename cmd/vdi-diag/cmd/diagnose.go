package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/p2well/vdi-diag/internal/checker"
	"github.com/p2well/vdi-diag/internal/checker/checks"
	"github.com/p2well/vdi-diag/internal/report"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var diagnoseCmd = &cobra.Command{
	Use:   "diagnose",
	Short: "Run on-demand diagnostic checks against VDI endpoints",
	Long: `Executes all diagnostic checks concurrently and produces a report.
Checks include DNS resolution, TCP connectivity, TLS validation,
HTTP endpoint health, ICA port reachability, and more.`,
	RunE: runDiagnose,
}

func init() {
	rootCmd.AddCommand(diagnoseCmd)
	diagnoseCmd.Flags().StringP("target", "t", "", "target VDI gateway URL (overrides config)")
	diagnoseCmd.Flags().StringP("output", "o", "text", "output format: text, json, html")
	diagnoseCmd.Flags().DurationP("timeout", "", 10*time.Second, "timeout for each check")
}

func runDiagnose(cmd *cobra.Command, args []string) error {
	target, _ := cmd.Flags().GetString("target")
	output, _ := cmd.Flags().GetString("output")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	verbose := viper.GetBool("verbose")

	if target == "" {
		target = viper.GetString("targets.0.url")
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "No target specified. Use --target or set targets in config file.")
		fmt.Fprintln(os.Stderr, "Example: vdi-diag diagnose --target https://yourcompany.cloud.com")
		os.Exit(1)
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	host := parsedURL.Hostname()
	if host == "" {
		host = target
	}

	ports := []int{443, 1494, 2598}

	allChecks := checks.BuildChecks(host, target, ports)

	fmt.Fprintf(os.Stderr, "🔍 Running %d diagnostic checks against %s...\n\n", len(allChecks), host)

	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Duration(len(allChecks)))
	defer cancel()

	results := runChecks(ctx, allChecks, timeout, verbose)

	return report.Render(results, output, os.Stdout)
}

func runChecks(ctx context.Context, checkers []checker.Checker, timeout time.Duration, verbose bool) []*checker.Result {
	results := make([]*checker.Result, len(checkers))
	var wg sync.WaitGroup

	for i, c := range checkers {
		wg.Add(1)
		go func(idx int, chk checker.Checker) {
			defer wg.Done()
			checkCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			if verbose {
				fmt.Fprintf(os.Stderr, "  ⏳ Running: %s\n", chk.Name())
			}

			results[idx] = chk.Run(checkCtx)
		}(i, c)
	}

	wg.Wait()
	return results
}
