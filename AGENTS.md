# Agents

Instructions for AI coding agents working on this repository.

## Project Overview

**vdi-diag** is a Go CLI tool for diagnosing VDI (Virtual Desktop Infrastructure) connectivity issues. It provides on-demand diagnostics and continuous monitoring to identify why ICA sessions fail to launch.

## Build and Test

```bash
# Build
go build ./cmd/vdi-diag

# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Vet for issues
go vet ./...
```

## Project Structure

```
cmd/vdi-diag/          Entry point and CLI commands (cobra)
internal/
  checker/             Checker interface and result types
  checker/checks/      Concrete check implementations
  config/              Configuration types and defaults
  network/             Low-level network probing (DNS, TCP, TLS, HTTP)
  report/              Output formatting (text, JSON, HTML)
```

## Coding Conventions

- Follow idiomatic Go practices (see `.copilot/instructions/go.instructions.md` if available)
- Use the `Checker` interface for all diagnostic checks
- Keep checks concurrent-safe (no shared mutable state)
- Use `context.Context` for timeouts and cancellation
- Wrap errors with `fmt.Errorf` using `%w` verb
- Use table-driven tests
- Do not hardcode vendor-specific names in user-facing output (use generic VDI terminology)

## Adding a New Check

1. Create a new type implementing `checker.Checker` in `internal/checker/checks/`
2. Implement `Name()`, `Description()`, `Severity()`, and `Run(ctx context.Context) *Result`
3. Register the check in `BuildChecks()` in `internal/checker/checks/checks.go`
4. Update the test count in `checks_test.go`
5. Add a row to the diagnostic checks table in `README.md`

## Important Notes

- This tool does NOT handle credentials or authentication
- Windows-specific checks use `os/exec` to call `netsh`, `powershell`, `tracert`, `ping`
- The tool should remain distributable as a single static binary
- Keep dependencies minimal (currently: cobra, viper)
- Remaining references to vendor names (e.g., in registry paths or VPN adapter detection) are intentional for functionality — do not add new vendor names to user-facing messages
