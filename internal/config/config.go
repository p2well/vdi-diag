// Package config provides configuration loading and defaults for vdi-diag.
package config

import "time"

// Config holds all configuration for the diagnostic tool.
type Config struct {
	Targets    []Target      `mapstructure:"targets"`
	Monitoring Monitoring    `mapstructure:"monitoring"`
	Alerts     Alerts        `mapstructure:"alerts"`
	Output     Output        `mapstructure:"output"`
	Timeout    time.Duration `mapstructure:"timeout"`
}

// Target defines a VDI endpoint to check.
type Target struct {
	Name  string `mapstructure:"name"`
	URL   string `mapstructure:"url"`
	Ports []int  `mapstructure:"ports"`
}

// Monitoring holds configuration for continuous monitoring mode.
type Monitoring struct {
	Interval time.Duration `mapstructure:"interval"`
	LogFile  string        `mapstructure:"log_file"`
}

// Alerts defines thresholds for alerting.
type Alerts struct {
	LatencyThresholdMs    int `mapstructure:"latency_threshold_ms"`
	ConsecutiveFailures   int `mapstructure:"consecutive_failures"`
	PacketLossPercentage  int `mapstructure:"packet_loss_percentage"`
}

// Output configures report output settings.
type Output struct {
	Format string `mapstructure:"format"`
	File   string `mapstructure:"file"`
}

// Default returns a Config with sensible defaults for VDI diagnostics.
func Default() *Config {
	return &Config{
		Targets: []Target{
			{
				Name:  "vdi-gateway",
				URL:   "https://yourcompany.cloud.com",
				Ports: []int{443, 1494, 2598},
			},
		},
		Monitoring: Monitoring{
			Interval: 30 * time.Second,
			LogFile:  "vdi-diag.log",
		},
		Alerts: Alerts{
			LatencyThresholdMs:   500,
			ConsecutiveFailures:  3,
			PacketLossPercentage: 5,
		},
		Output: Output{
			Format: "text",
		},
		Timeout: 10 * time.Second,
	}
}
