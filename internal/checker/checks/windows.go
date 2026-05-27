package checks

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/p2well/vdi-diag/internal/checker"
)

// ProxyChecker detects system proxy settings that may interfere with VDI connections.
type ProxyChecker struct{}

// NewProxyChecker creates a proxy detection checker.
func NewProxyChecker() *ProxyChecker {
	return &ProxyChecker{}
}

func (c *ProxyChecker) Name() string        { return "Proxy Detection" }
func (c *ProxyChecker) Description() string  { return "Detects system proxy settings that may interfere" }
func (c *ProxyChecker) Severity() checker.Severity { return checker.SeverityWarning }

func (c *ProxyChecker) Run(ctx context.Context) *checker.Result {
	start := time.Now()
	r := &checker.Result{
		Name:     c.Name(),
		Severity: c.Severity(),
	}

	// Check WinHTTP proxy settings.
	cmd := exec.CommandContext(ctx, "netsh", "winhttp", "show", "proxy")
	output, err := cmd.Output()
	r.Duration = time.Since(start)

	if err != nil {
		r.Status = checker.StatusFail
		r.Message = "Failed to check proxy settings"
		r.Details = err.Error()
		r.Error = err
		return r
	}

	outputStr := string(output)
	outputLower := strings.ToLower(outputStr)
	if strings.Contains(outputLower, "directaccess") ||
		strings.Contains(outputLower, "direct access") ||
		strings.Contains(outputLower, "kein proxy") ||
		strings.Contains(outputLower, "no proxy") {
		r.Status = checker.StatusPass
		r.Message = "No proxy configured (direct access)"
		return r
	}

	r.Status = checker.StatusPass
	r.Severity = checker.SeverityWarning
	r.Message = "Proxy detected - may interfere with ICA connections"
	r.Details = strings.TrimSpace(outputStr)
	return r
}

// FirewallChecker checks Windows Firewall rules for VDI ports.
type FirewallChecker struct {
	host  string
	ports []int
}

// NewFirewallChecker creates a firewall rule checker.
func NewFirewallChecker(host string, ports []int) *FirewallChecker {
	return &FirewallChecker{host: host, ports: ports}
}

func (c *FirewallChecker) Name() string        { return "Windows Firewall" }
func (c *FirewallChecker) Description() string  { return "Checks if firewall rules block VDI ports" }
func (c *FirewallChecker) Severity() checker.Severity { return checker.SeverityWarning }

func (c *FirewallChecker) Run(ctx context.Context) *checker.Result {
	start := time.Now()
	r := &checker.Result{
		Name:     c.Name(),
		Severity: c.Severity(),
	}

	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=out")
	output, err := cmd.Output()
	r.Duration = time.Since(start)

	if err != nil {
		r.Status = checker.StatusFail
		r.Message = "Failed to query firewall rules"
		r.Details = err.Error()
		r.Error = err
		return r
	}

	var blockedPorts []int
	outputStr := string(output)
	for _, port := range c.ports {
		portStr := fmt.Sprintf("%d", port)
		if strings.Contains(outputStr, portStr) && strings.Contains(outputStr, "Block") {
			blockedPorts = append(blockedPorts, port)
		}
	}

	if len(blockedPorts) > 0 {
		r.Status = checker.StatusFail
		r.Severity = checker.SeverityCritical
		r.Message = fmt.Sprintf("Firewall may be blocking ports: %v", blockedPorts)
		r.Details = "Outbound block rules found for VDI ports. This can prevent ICA sessions."
		return r
	}

	r.Status = checker.StatusPass
	r.Message = "No outbound block rules found for VDI ports"
	return r
}

// MTUChecker detects MTU/fragmentation issues.
type MTUChecker struct {
	host string
}

// NewMTUChecker creates an MTU checker.
func NewMTUChecker(host string) *MTUChecker {
	return &MTUChecker{host: host}
}

func (c *MTUChecker) Name() string        { return "MTU / Fragmentation" }
func (c *MTUChecker) Description() string  { return "Detects MTU issues that can cause ICA drops" }
func (c *MTUChecker) Severity() checker.Severity { return checker.SeverityWarning }

func (c *MTUChecker) Run(ctx context.Context) *checker.Result {
	start := time.Now()
	r := &checker.Result{
		Name:     c.Name(),
		Severity: c.Severity(),
	}

	// Ping with DF flag and 1472 bytes (1500 MTU - 28 bytes header).
	cmd := exec.CommandContext(ctx, "ping", "-n", "1", "-f", "-l", "1472", c.host)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	r.Duration = time.Since(start)

	output := stdout.String() + stderr.String()
	outputLower := strings.ToLower(output)

	// Detect fragmentation in any locale (English: "fragmented", German: "fragmentiert").
	hasFragmentation := strings.Contains(outputLower, "fragment")

	if err != nil || hasFragmentation {
		// Try smaller size to find working MTU.
		cmd2 := exec.CommandContext(ctx, "ping", "-n", "1", "-f", "-l", "1400", c.host)
		output2, err2 := cmd2.Output()
		output2Lower := strings.ToLower(string(output2))

		// Check for a successful reply in any locale.
		pingSuccess := strings.Contains(output2Lower, "ttl") ||
			strings.Contains(output2Lower, "reply") ||
			strings.Contains(output2Lower, "antwort")

		if pingSuccess {
			r.Status = checker.StatusPass
			r.Severity = checker.SeverityWarning
			r.Message = "MTU is below 1500 (works at 1400)"
			r.Details = "Path MTU is between 1428-1500 bytes. This may cause fragmentation with large ICA packets."
			return r
		}

		// Second ping also failed. Check if it's also fragmentation or ICMP blocked.
		output2HasFrag := strings.Contains(output2Lower, "fragment")
		if output2HasFrag {
			// Both sizes fragment — MTU is very low.
			r.Status = checker.StatusFail
			r.Severity = checker.SeverityWarning
			r.Message = "MTU is below 1428"
			r.Details = "Path MTU is below 1428 bytes. Consider lowering the ICA session MTU."
			return r
		}

		// ICMP appears blocked by the destination — cannot determine MTU.
		if err2 != nil && !hasFragmentation {
			r.Status = checker.StatusPass
			r.Severity = checker.SeverityInfo
			r.Message = "MTU check inconclusive (ICMP blocked)"
			r.Details = "The destination does not respond to ICMP ping. MTU cannot be verified."
			return r
		}

		// Fragmentation at 1472 but ICMP blocked at 1400 — real MTU issue
		// but not critical since TCP/HTTPS handles segmentation.
		r.Status = checker.StatusPass
		r.Severity = checker.SeverityWarning
		r.Message = "Path MTU likely below 1500 (ICMP blocked at destination)"
		r.Details = "Fragmentation detected at 1472 bytes but destination does not respond to ICMP. " +
			"TCP-based VDI sessions handle segmentation automatically via the gateway."
		return r
	}

	r.Status = checker.StatusPass
	r.Message = "MTU 1500 supported (no fragmentation needed)"
	return r
}

// TracerouteChecker traces the route to identify problematic hops.
type TracerouteChecker struct {
	host string
}

// NewTracerouteChecker creates a traceroute checker.
func NewTracerouteChecker(host string) *TracerouteChecker {
	return &TracerouteChecker{host: host}
}

func (c *TracerouteChecker) Name() string        { return "Route Trace" }
func (c *TracerouteChecker) Description() string  { return "Traces network route to identify problematic hops" }
func (c *TracerouteChecker) Severity() checker.Severity { return checker.SeverityInfo }

func (c *TracerouteChecker) Run(ctx context.Context) *checker.Result {
	start := time.Now()
	r := &checker.Result{
		Name:     c.Name(),
		Severity: c.Severity(),
	}

	cmd := exec.CommandContext(ctx, "tracert", "-d", "-w", "2000", "-h", "15", c.host)
	output, err := cmd.Output()
	r.Duration = time.Since(start)

	if err != nil {
		// Tracert may exit non-zero but still produce useful output.
		if len(output) == 0 {
			r.Status = checker.StatusFail
			r.Message = "Traceroute failed"
			r.Details = err.Error()
			r.Error = err
			return r
		}
	}

	outputStr := string(output)
	timeoutHops := strings.Count(outputStr, "Request timed out")
	lines := strings.Split(outputStr, "\n")
	hopCount := 0
	for _, line := range lines {
		if strings.Contains(line, "ms") || strings.Contains(line, "*") {
			hopCount++
		}
	}

	r.Status = checker.StatusPass
	r.Message = fmt.Sprintf("Route traced: %d hops, %d timeouts", hopCount, timeoutHops)

	if timeoutHops > 3 {
		r.Severity = checker.SeverityWarning
		r.Details = fmt.Sprintf("Multiple hops timing out (%d), indicating possible routing issues.\n\n%s", timeoutHops, outputStr)
	} else {
		r.Details = outputStr
	}

	return r
}

// VDIClientChecker detects the VDI client installation and status.
type VDIClientChecker struct{}

// NewVDIClientChecker creates a VDI client checker.
func NewVDIClientChecker() *VDIClientChecker {
	return &VDIClientChecker{}
}

func (c *VDIClientChecker) Name() string        { return "VDI Client Status" }
func (c *VDIClientChecker) Description() string  { return "Detects installed VDI client version and running processes" }
func (c *VDIClientChecker) Severity() checker.Severity { return checker.SeverityInfo }

func (c *VDIClientChecker) Run(ctx context.Context) *checker.Result {
	start := time.Now()
	r := &checker.Result{
		Name:     c.Name(),
		Severity: c.Severity(),
	}

	// Check for running VDI client processes.
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		"Get-Process -Name 'wfica*','Receiver*','SelfService*','AuthManSvr*','concentr*' -ErrorAction SilentlyContinue | Select-Object Name,Id,CPU | Format-Table -AutoSize")
	output, err := cmd.Output()
	r.Duration = time.Since(start)

	if err != nil || len(strings.TrimSpace(string(output))) == 0 {
		r.Status = checker.StatusPass
		r.Severity = checker.SeverityWarning
		r.Message = "No VDI client processes detected"
		r.Details = "VDI client may not be running. Ensure it is installed and started."
		return r
	}

	// Check version from registry (supports common VDI clients).
	versionCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		"(Get-ItemProperty 'HKLM:\\SOFTWARE\\WOW6432Node\\Citrix\\Dazzle' -ErrorAction SilentlyContinue).ProductVersion")
	versionOutput, _ := versionCmd.Output()
	version := strings.TrimSpace(string(versionOutput))

	r.Status = checker.StatusPass
	r.Message = fmt.Sprintf("VDI client is running (version: %s)", version)
	r.Details = strings.TrimSpace(string(output))
	return r
}
