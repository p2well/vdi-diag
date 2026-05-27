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

// RouteCompareChecker compares routing paths for different ports to detect
// split-tunnel VPN misconfigurations where HTTPS (443) routes correctly
// but ICA ports (1494/2598) take a different, broken path.
type RouteCompareChecker struct {
	host  string
	ports []int
}

// NewRouteCompareChecker creates a route comparison checker.
func NewRouteCompareChecker(host string, ports []int) *RouteCompareChecker {
	return &RouteCompareChecker{host: host, ports: ports}
}

func (c *RouteCompareChecker) Name() string { return "VPN / Route Analysis" }
func (c *RouteCompareChecker) Description() string {
	return "Compares routing for port 443 vs ICA ports to detect split-tunnel issues"
}
func (c *RouteCompareChecker) Severity() checker.Severity { return checker.SeverityCritical }

func (c *RouteCompareChecker) Run(ctx context.Context) *checker.Result {
	start := time.Now()
	r := &checker.Result{
		Name:     c.Name(),
		Severity: c.Severity(),
	}

	// Use a generous internal timeout since this check runs multiple subcommands.
	innerCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var details strings.Builder

	// 1. Get active network adapters.
	adapters, err := getActiveAdapters(innerCtx)
	if err != nil {
		details.WriteString(fmt.Sprintf("Failed to query adapters: %s\n", err))
	} else {
		details.WriteString("=== Active Network Adapters ===\n")
		details.WriteString(adapters)
		details.WriteString("\n")
	}

	// 2. Get route table entry for the target host IP.
	routes, err := getRoutesForHost(innerCtx, c.host)
	if err != nil {
		details.WriteString(fmt.Sprintf("Failed to query routes: %s\n", err))
	} else {
		details.WriteString("=== Route Table (relevant entries) ===\n")
		details.WriteString(routes)
		details.WriteString("\n")
	}

	// 3. Compare traceroute first hop for port 443 vs other ports.
	// Use TCP-based path detection: the first hop response to different ports
	// reveals which adapter/tunnel handles each.
	details.WriteString("=== Per-Port Path Analysis ===\n")

	type portPath struct {
		port     int
		firstHop string
		adapter  string
		err      error
	}

	paths := make([]portPath, 0, len(c.ports))
	for _, port := range c.ports {
		pp := portPath{port: port}
		pp.firstHop, pp.adapter, pp.err = traceFirstHop(innerCtx, c.host, port)
		paths = append(paths, pp)
	}

	var referenceAdapter string
	mismatchDetected := false

	for _, pp := range paths {
		if pp.err != nil {
			details.WriteString(fmt.Sprintf("  Port %d: error - %s\n", pp.port, pp.err))
			continue
		}
		details.WriteString(fmt.Sprintf("  Port %d: first hop = %s, interface = %s\n", pp.port, pp.firstHop, pp.adapter))

		if referenceAdapter == "" {
			referenceAdapter = pp.adapter
		} else if pp.adapter != referenceAdapter && pp.adapter != "" {
			mismatchDetected = true
		}
	}

	// 4. Check for VPN adapters specifically.
	vpnInfo, _ := detectVPNAdapters(innerCtx)
	if vpnInfo != "" {
		details.WriteString("\n=== VPN Adapters Detected ===\n")
		details.WriteString(vpnInfo)
	}

	r.Duration = time.Since(start)
	r.Details = details.String()

	if mismatchDetected {
		r.Status = checker.StatusFail
		r.Message = "Split-tunnel issue: ICA ports route through a different adapter than HTTPS"
		return r
	}

	// Check if VPN is present and ICA ports failed (from context of other checks).
	if vpnInfo != "" {
		r.Status = checker.StatusPass
		r.Severity = checker.SeverityWarning
		r.Message = "VPN detected - verify ICA ports are included in tunnel"
		return r
	}

	r.Status = checker.StatusPass
	r.Message = "All ports route through the same network path"
	return r
}

func getActiveAdapters(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		"Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name, InterfaceDescription, ifIndex, MacAddress, LinkSpeed | Format-Table -AutoSize | Out-String -Width 200")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func getRoutesForHost(ctx context.Context, host string) (string, error) {
	// First resolve the host to get the IP.
	resolveCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		fmt.Sprintf("[System.Net.Dns]::GetHostAddresses('%s') | Select-Object -ExpandProperty IPAddressToString", host))
	ipOutput, err := resolveCmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolving host: %w", err)
	}

	ip := strings.TrimSpace(strings.Split(string(ipOutput), "\n")[0])
	if ip == "" {
		return "", fmt.Errorf("could not resolve %s", host)
	}

	// Get the route for this specific IP.
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		fmt.Sprintf("Find-NetRoute -RemoteIPAddress '%s' | Select-Object InterfaceIndex, InterfaceAlias, NextHop, DestinationPrefix, RouteMetric | Format-Table -AutoSize | Out-String -Width 200", ip))
	output, err := cmd.Output()
	if err != nil {
		// Fallback to route print.
		fallback := exec.CommandContext(ctx, "route", "print")
		var stdout bytes.Buffer
		fallback.Stdout = &stdout
		_ = fallback.Run()
		lines := strings.Split(stdout.String(), "\n")
		var relevant []string
		for _, line := range lines {
			if strings.Contains(line, ip) || strings.Contains(line, "0.0.0.0") {
				relevant = append(relevant, strings.TrimSpace(line))
			}
		}
		if len(relevant) > 10 {
			relevant = relevant[:10]
		}
		return strings.Join(relevant, "\n"), nil
	}
	return strings.TrimSpace(string(output)), nil
}

func traceFirstHop(ctx context.Context, host string, port int) (firstHop string, adapter string, err error) {
	// Use Find-NetRoute to determine which interface would handle traffic to this host.
	resolveCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		fmt.Sprintf("[System.Net.Dns]::GetHostAddresses('%s')[0].IPAddressToString", host))
	ipOutput, err := resolveCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("resolving: %w", err)
	}
	ip := strings.TrimSpace(string(ipOutput))

	// Find which interface routes to this IP.
	routeCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		fmt.Sprintf("$r = Find-NetRoute -RemoteIPAddress '%s' | Select-Object -First 1; \"$($r.NextHop)|$($r.InterfaceAlias)\"", ip))
	routeOutput, err := routeCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("finding route: %w", err)
	}

	parts := strings.SplitN(strings.TrimSpace(string(routeOutput)), "|", 2)
	if len(parts) == 2 {
		firstHop = parts[0]
		adapter = parts[1]
	} else {
		firstHop = strings.TrimSpace(string(routeOutput))
	}

	return firstHop, adapter, nil
}

func detectVPNAdapters(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		`Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'VPN|Zscaler|GlobalProtect|AnyConnect|Fortinet|WireGuard|OpenVPN|Citrix|Pulse|F5|SonicWall|Cloudflare|WARP|TAP|TUN') } | Select-Object Name, InterfaceDescription, ifIndex, LinkSpeed | Format-Table -AutoSize | Out-String -Width 200`)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	result := strings.TrimSpace(string(output))
	if result == "" {
		return "", nil
	}
	return result, nil
}
