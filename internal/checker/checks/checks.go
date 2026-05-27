// Package checks provides concrete implementations of diagnostic checkers.
package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/p2well/vdi-diag/internal/checker"
	"github.com/p2well/vdi-diag/internal/network"
)

// DNSChecker verifies DNS resolution for a host.
type DNSChecker struct {
	host string
}

// NewDNSChecker creates a DNS resolution checker.
func NewDNSChecker(host string) *DNSChecker {
	return &DNSChecker{host: host}
}

func (c *DNSChecker) Name() string        { return "DNS Resolution" }
func (c *DNSChecker) Description() string  { return "Resolves the target hostname and measures latency" }
func (c *DNSChecker) Severity() checker.Severity { return checker.SeverityCritical }

func (c *DNSChecker) Run(ctx context.Context) *checker.Result {
	start := time.Now()
	result := network.ResolveDNS(ctx, c.host)

	r := &checker.Result{
		Name:     c.Name(),
		Severity: c.Severity(),
		Duration: time.Since(start),
	}

	if result.Error != nil {
		r.Status = checker.StatusFail
		r.Message = fmt.Sprintf("DNS resolution failed for %s", c.host)
		r.Details = result.Error.Error()
		r.Error = result.Error
		return r
	}

	r.Status = checker.StatusPass
	r.Message = fmt.Sprintf("Resolved %s to %s in %s",
		c.host, strings.Join(result.Addresses, ", "), result.Duration.Round(time.Millisecond))

	if result.Duration > 500*time.Millisecond {
		r.Details = "DNS resolution is slow (>500ms); this may impact session launch"
		r.Severity = checker.SeverityWarning
	}

	return r
}

// TCPChecker verifies TCP connectivity to a host:port.
type TCPChecker struct {
	host string
	port int
}

// NewTCPChecker creates a TCP connectivity checker.
func NewTCPChecker(host string, port int) *TCPChecker {
	return &TCPChecker{host: host, port: port}
}

func (c *TCPChecker) Name() string { return fmt.Sprintf("TCP Port %d", c.port) }
func (c *TCPChecker) Description() string {
	return fmt.Sprintf("Verifies TCP connectivity to %s:%d", c.host, c.port)
}
func (c *TCPChecker) Severity() checker.Severity {
	if c.port == 443 {
		return checker.SeverityCritical
	}
	return checker.SeverityCritical
}

func (c *TCPChecker) Run(ctx context.Context) *checker.Result {
	start := time.Now()
	result := network.DialTCP(ctx, c.host, c.port)

	r := &checker.Result{
		Name:     c.Name(),
		Severity: c.Severity(),
		Duration: time.Since(start),
	}

	if result.Error != nil {
		r.Status = checker.StatusFail
		r.Message = fmt.Sprintf("Cannot connect to %s:%d", c.host, c.port)
		r.Details = result.Error.Error()
		r.Error = result.Error
		return r
	}

	r.Status = checker.StatusPass
	r.Message = fmt.Sprintf("Connected to %s:%d in %s", c.host, c.port, result.Duration.Round(time.Millisecond))

	if result.Duration > 1*time.Second {
		r.Details = "Connection is slow (>1s); may cause ICA timeouts"
		r.Severity = checker.SeverityWarning
	}

	return r
}

// TLSChecker verifies TLS handshake and certificate health.
type TLSChecker struct {
	host string
	port int
}

// NewTLSChecker creates a TLS handshake checker.
func NewTLSChecker(host string, port int) *TLSChecker {
	return &TLSChecker{host: host, port: port}
}

func (c *TLSChecker) Name() string        { return fmt.Sprintf("TLS Handshake (port %d)", c.port) }
func (c *TLSChecker) Description() string  { return "Validates TLS handshake and certificate chain" }
func (c *TLSChecker) Severity() checker.Severity { return checker.SeverityCritical }

func (c *TLSChecker) Run(ctx context.Context) *checker.Result {
	start := time.Now()
	result := network.CheckTLS(ctx, c.host, c.port)

	r := &checker.Result{
		Name:     c.Name(),
		Severity: c.Severity(),
		Duration: time.Since(start),
	}

	if result.Error != nil {
		r.Status = checker.StatusFail
		r.Message = fmt.Sprintf("TLS handshake failed on %s:%d", c.host, c.port)
		r.Details = result.Error.Error()
		r.Error = result.Error
		return r
	}

	r.Status = checker.StatusPass
	r.Message = fmt.Sprintf("TLS %s, cert expires %s, issuer: %s",
		network.TLSVersionString(result.Version),
		result.CertExpiry.Format("2006-01-02"),
		result.CertIssuer)

	// Warn if certificate expires within 30 days.
	if time.Until(result.CertExpiry) < 30*24*time.Hour {
		r.Severity = checker.SeverityWarning
		r.Details = fmt.Sprintf("Certificate expires in %d days", int(time.Until(result.CertExpiry).Hours()/24))
	}

	return r
}

// HTTPChecker verifies HTTP endpoint health.
type HTTPChecker struct {
	url string
}

// NewHTTPChecker creates an HTTP endpoint checker.
func NewHTTPChecker(url string) *HTTPChecker {
	return &HTTPChecker{url: url}
}

func (c *HTTPChecker) Name() string        { return "HTTPS Endpoint" }
func (c *HTTPChecker) Description() string  { return "Checks HTTPS endpoint responds correctly" }
func (c *HTTPChecker) Severity() checker.Severity { return checker.SeverityCritical }

func (c *HTTPChecker) Run(ctx context.Context) *checker.Result {
	start := time.Now()
	result := network.ProbeHTTP(ctx, c.url)

	r := &checker.Result{
		Name:     c.Name(),
		Severity: c.Severity(),
		Duration: time.Since(start),
	}

	if result.Error != nil {
		r.Status = checker.StatusFail
		r.Message = fmt.Sprintf("HTTP request to %s failed", c.url)
		r.Details = result.Error.Error()
		r.Error = result.Error
		return r
	}

	if result.StatusCode >= 500 {
		r.Status = checker.StatusFail
		r.Message = fmt.Sprintf("Server error: HTTP %d from %s", result.StatusCode, c.url)
		return r
	}

	r.Status = checker.StatusPass
	r.Message = fmt.Sprintf("HTTP %d from %s in %s", result.StatusCode, c.url, result.Duration.Round(time.Millisecond))

	if result.Duration > 3*time.Second {
		r.Severity = checker.SeverityWarning
		r.Details = "HTTP response is slow (>3s)"
	}

	return r
}

// BuildChecks returns all diagnostic checks for a given host and ports.
func BuildChecks(host, targetURL string, ports []int) []checker.Checker {
	var allChecks []checker.Checker

	// DNS check.
	allChecks = append(allChecks, NewDNSChecker(host))

	// TCP and TLS checks for each port.
	for _, port := range ports {
		allChecks = append(allChecks, NewTCPChecker(host, port))
		if port == 443 {
			allChecks = append(allChecks, NewTLSChecker(host, port))
		}
	}

	// HTTP endpoint check.
	allChecks = append(allChecks, NewHTTPChecker(targetURL))

	// Windows-specific checks.
	allChecks = append(allChecks, NewProxyChecker())
	allChecks = append(allChecks, NewFirewallChecker(host, ports))
	allChecks = append(allChecks, NewMTUChecker(host))
	allChecks = append(allChecks, NewTracerouteChecker(host))
	allChecks = append(allChecks, NewRouteCompareChecker(host, ports))
	allChecks = append(allChecks, NewVDIClientChecker())

	return allChecks
}
