// Package checker defines the diagnostic check interface and result types.
package checker

import (
	"context"
	"time"
)

// Severity indicates the importance level of a check result.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityCritical
)

// String returns the human-readable severity label.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARN"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Status represents the outcome of a diagnostic check.
type Status int

const (
	StatusPass Status = iota
	StatusFail
	StatusSkipped
)

// String returns the human-readable status label.
func (s Status) String() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusFail:
		return "FAIL"
	case StatusSkipped:
		return "SKIP"
	default:
		return "UNKNOWN"
	}
}

// Result holds the outcome of a single diagnostic check.
type Result struct {
	Name     string        `json:"name"`
	Status   Status        `json:"status"`
	Severity Severity      `json:"severity"`
	Message  string        `json:"message"`
	Details  string        `json:"details,omitempty"`
	Duration time.Duration `json:"duration"`
	Error    error         `json:"-"`
}

// Checker is the interface that all diagnostic checks must implement.
type Checker interface {
	// Name returns the human-readable name of the check.
	Name() string

	// Description returns a brief explanation of what the check verifies.
	Description() string

	// Severity returns the importance level if this check fails.
	Severity() Severity

	// Run executes the diagnostic check and returns the result.
	Run(ctx context.Context) *Result
}
