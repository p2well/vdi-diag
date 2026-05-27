package checks

import (
	"context"
	"testing"
	"time"

	"github.com/p2well/vdi-diag/internal/checker"
)

func TestDNSChecker_Run(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		wantStatus checker.Status
	}{
		{
			name:       "valid host resolves",
			host:       "google.com",
			wantStatus: checker.StatusPass,
		},
		{
			name:       "invalid host fails",
			host:       "this-host-does-not-exist-xyz123.invalid",
			wantStatus: checker.StatusFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			c := NewDNSChecker(tt.host)
			result := c.Run(ctx)

			if result.Status != tt.wantStatus {
				t.Errorf("DNSChecker.Run() status = %v, want %v (message: %s)",
					result.Status, tt.wantStatus, result.Message)
			}

			if result.Duration == 0 {
				t.Error("DNSChecker.Run() duration should be non-zero")
			}
		})
	}
}

func TestTCPChecker_Run(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		port       int
		wantStatus checker.Status
	}{
		{
			name:       "port 443 on google",
			host:       "google.com",
			port:       443,
			wantStatus: checker.StatusPass,
		},
		{
			name:       "unreachable port fails",
			host:       "127.0.0.1",
			port:       19999,
			wantStatus: checker.StatusFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			c := NewTCPChecker(tt.host, tt.port)
			result := c.Run(ctx)

			if result.Status != tt.wantStatus {
				t.Errorf("TCPChecker.Run() status = %v, want %v (message: %s)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestTLSChecker_Run(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c := NewTLSChecker("google.com", 443)
	result := c.Run(ctx)

	if result.Status != checker.StatusPass {
		t.Errorf("TLSChecker.Run() status = %v, want PASS (message: %s, details: %s)",
			result.Status, result.Message, result.Details)
	}

	if result.Duration == 0 {
		t.Error("TLSChecker.Run() duration should be non-zero")
	}
}

func TestHTTPChecker_Run(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantStatus checker.Status
	}{
		{
			name:       "valid HTTPS endpoint",
			url:        "https://www.google.com",
			wantStatus: checker.StatusPass,
		},
		{
			name:       "invalid endpoint",
			url:        "https://this-does-not-exist-xyz.invalid",
			wantStatus: checker.StatusFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			c := NewHTTPChecker(tt.url)
			result := c.Run(ctx)

			if result.Status != tt.wantStatus {
				t.Errorf("HTTPChecker.Run() status = %v, want %v (message: %s)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestBuildChecks(t *testing.T) {
	checks := BuildChecks("example.com", "https://example.com", []int{443, 1494, 2598})

	// Expected: DNS + 3 TCP + 1 TLS + HTTP + Proxy + Firewall + MTU + Traceroute + RouteCompare + VDIClient = 12
	expectedCount := 12
	if len(checks) != expectedCount {
		t.Errorf("BuildChecks() returned %d checks, want %d", len(checks), expectedCount)
	}

	// Verify all checkers have names.
	for i, c := range checks {
		if c.Name() == "" {
			t.Errorf("check[%d] has empty name", i)
		}
	}
}
