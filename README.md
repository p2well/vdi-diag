# vdi-diag

A professional Go-based diagnostic and monitoring tool for troubleshooting Virtual Desktop Infrastructure (VDI) connectivity issues. Specifically designed to identify why ICA sessions fail to launch after successful authentication.

> *This project is not affiliated with, endorsed by, or sponsored by Citrix Systems, Inc., VMware, Inc., or any other VDI vendor. "Citrix", "Citrix Workspace", and "ICA" are trademarks of Cloud Software Group, Inc. All other trademarks are the property of their respective owners.*

## Features

- **On-demand diagnostics** — Run comprehensive connectivity checks and get an instant report
- **Continuous monitoring** — Observe network health over time with structured logging and alerting
- **Multi-layer probing** — DNS, TCP, TLS, HTTPS, ICA ports, MTU, proxy, firewall, traceroute
- **VPN/Route analysis** — Detects split-tunnel misconfigurations where HTTPS works but ICA ports don't
- **Windows-native** — Detects VDI client status, WinHTTP proxy, and firewall rules
- **Multiple output formats** — Text (colorized), JSON (machine-readable), HTML (shareable reports)
- **Concurrent checks** — All diagnostics run in parallel using Go goroutines for speed

## Installation

```bash
go build -o vdi-diag.exe ./cmd/vdi-diag
```

## Quick Start

```bash
# Run diagnostics against your VDI gateway URL
vdi-diag diagnose --target https://yourcompany.cloud.com

# Generate an HTML report
vdi-diag diagnose --target https://yourcompany.cloud.com --output html > report.html

# Start continuous monitoring
vdi-diag monitor --target https://yourcompany.cloud.com --interval 30s

# Create a default config file
vdi-diag config init
```

## Commands

| Command | Description |
|---------|-------------|
| `diagnose` | Run all diagnostic checks and produce a report |
| `monitor` | Continuously monitor connectivity with alerting |
| `report` | Generate formatted reports from results |
| `config init` | Create a default configuration file |

## Diagnostic Checks

| Check | What it verifies |
|-------|-----------------|
| DNS Resolution | Resolves hostname, measures latency |
| TCP Connectivity | Connects to ports 443, 1494, 2598 |
| TLS Handshake | Validates certificate chain and expiry |
| HTTPS Endpoint | Checks HTTP status and response time |
| ICA Port Reachability | Probes ports 1494 (ICA) and 2598 (CGP) |
| MTU / Fragmentation | Detects path MTU issues |
| Proxy Detection | Finds WinHTTP proxy settings |
| Windows Firewall | Checks for blocking rules |
| Route Trace | Identifies problematic network hops |
| VPN / Route Analysis | Compares routing for port 443 vs ICA ports |
| VDI Client Status | Detects version and running processes |

## Configuration

Create `vdi-diag.yaml` in the current directory or home folder:

```yaml
targets:
  - name: vdi-gateway
    url: https://yourcompany.cloud.com
    ports: [443, 1494, 2598]

monitoring:
  interval: 30s
  log_file: vdi-diag.log

alerts:
  latency_threshold_ms: 500
  consecutive_failures: 3

timeout: 10s
```

## Troubleshooting Common Issues

### ICA Ports Blocked (1494/2598)
If TCP checks fail on ports 1494 or 2598, ICA sessions cannot launch. Common causes:
- Corporate firewall blocking outbound connections
- VPN split-tunneling not including VDI gateway ranges
- Network proxy not configured for these ports

### VPN Split-Tunnel Mismatch
The VPN/Route Analysis check detects when port 443 routes through one adapter but ICA ports route differently. Fix by ensuring your VPN includes the VDI gateway in its tunnel.

### MTU Fragmentation
Path MTU below 1500 can cause large ICA packets to be dropped. Solutions:
- Adjust MTU on VPN adapter
- Contact network team to fix path MTU

### High Latency
DNS or TCP latency above 500ms may cause session timeouts. Check:
- DNS server responsiveness
- Network congestion on the path to the VDI gateway

## Development

```bash
# Run tests
go test ./...

# Build
go build ./cmd/vdi-diag

# Run with verbose output
vdi-diag diagnose --target https://yourcompany.cloud.com -v
```

## License

See [LICENSE](LICENSE) file.
owner - pawel.pawluk@accenture.com
