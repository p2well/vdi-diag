package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/p2well/vdi-diag/internal/checker"
	"github.com/p2well/vdi-diag/internal/checker/checks"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Continuously monitor VDI connectivity",
	Long: `Runs diagnostic checks at regular intervals and logs results.
Alerts when consecutive failures exceed the configured threshold.
Press Ctrl+C to stop.`,
	RunE: runMonitor,
}

func init() {
	rootCmd.AddCommand(monitorCmd)
	monitorCmd.Flags().DurationP("interval", "i", 30*time.Second, "check interval")
	monitorCmd.Flags().StringP("target", "t", "", "target VDI gateway URL")
	monitorCmd.Flags().StringP("log-file", "l", "vdi-diag.log", "log file path")
	monitorCmd.Flags().IntP("alert-threshold", "a", 3, "consecutive failures before alerting")
}

func runMonitor(cmd *cobra.Command, args []string) error {
	target, _ := cmd.Flags().GetString("target")
	interval, _ := cmd.Flags().GetDuration("interval")
	logFile, _ := cmd.Flags().GetString("log-file")
	alertThreshold, _ := cmd.Flags().GetInt("alert-threshold")

	if target == "" {
		target = viper.GetString("targets.0.url")
	}
	if target == "" {
		return fmt.Errorf("no target specified; use --target or set targets in config")
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	host := parsedURL.Hostname()
	if host == "" {
		host = target
	}

	// Setup structured logging to file.
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("opening log file: %w", err)
	}
	defer f.Close()

	logger := slog.New(slog.NewJSONHandler(f, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ports := []int{443, 1494, 2598}
	allChecks := checks.BuildChecks(host, target, ports)

	fmt.Fprintf(os.Stderr, "📡 Monitoring %s every %s (logging to %s)\n", host, interval, logFile)
	fmt.Fprintf(os.Stderr, "   Alert after %d consecutive failures. Press Ctrl+C to stop.\n\n", alertThreshold)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\n🛑 Shutting down monitor...\n")
		cancel()
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	consecutiveFailures := 0
	iteration := 0

	// Run immediately on start.
	runMonitorIteration(ctx, allChecks, logger, &consecutiveFailures, alertThreshold, &iteration)

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "Monitor stopped after %d iterations.\n", iteration)
			return nil
		case <-ticker.C:
			runMonitorIteration(ctx, allChecks, logger, &consecutiveFailures, alertThreshold, &iteration)
		}
	}
}

func runMonitorIteration(ctx context.Context, allChecks []checker.Checker, logger *slog.Logger, consecutiveFailures *int, alertThreshold int, iteration *int) {
	*iteration++
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	results := make([]*checker.Result, 0, len(allChecks))
	for _, c := range allChecks {
		results = append(results, c.Run(checkCtx))
	}

	hasFailure := false
	for _, r := range results {
		entry := logger.With(
			slog.Int("iteration", *iteration),
			slog.String("check", r.Name),
			slog.String("status", r.Status.String()),
			slog.String("severity", r.Severity.String()),
			slog.Duration("duration", r.Duration),
		)

		if r.Status == checker.StatusFail {
			hasFailure = true
			entry.Error("check failed", slog.String("message", r.Message), slog.String("details", r.Details))
		} else {
			entry.Info("check passed", slog.String("message", r.Message))
		}
	}

	if hasFailure {
		*consecutiveFailures++
		if *consecutiveFailures >= alertThreshold {
			fmt.Fprintf(os.Stderr, "⚠️  ALERT [iter %d]: %d consecutive failures detected!\n", *iteration, *consecutiveFailures)
			logAlert(logger, *iteration, *consecutiveFailures, results)
		} else {
			fmt.Fprintf(os.Stderr, "❌ [iter %d] Failures detected (%d/%d before alert)\n", *iteration, *consecutiveFailures, alertThreshold)
		}
	} else {
		if *consecutiveFailures > 0 {
			fmt.Fprintf(os.Stderr, "✅ [iter %d] Recovered after %d failures\n", *iteration, *consecutiveFailures)
		} else {
			fmt.Fprintf(os.Stderr, "✅ [iter %d] All checks passed\n", *iteration)
		}
		*consecutiveFailures = 0
	}
}

func logAlert(logger *slog.Logger, iteration int, failures int, results []*checker.Result) {
	failedChecks := make([]string, 0)
	for _, r := range results {
		if r.Status == checker.StatusFail {
			data, _ := json.Marshal(r)
			failedChecks = append(failedChecks, string(data))
		}
	}

	logger.Warn("ALERT: consecutive failures threshold exceeded",
		slog.Int("iteration", iteration),
		slog.Int("consecutive_failures", failures),
		slog.Any("failed_checks", failedChecks),
	)
}
