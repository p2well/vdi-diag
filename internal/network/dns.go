// Package network provides low-level network probing utilities.
package network

import (
	"context"
	"fmt"
	"net"
	"time"
)

// DNSResult holds the outcome of a DNS resolution.
type DNSResult struct {
	Host      string
	Addresses []string
	Duration  time.Duration
	Error     error
}

// ResolveDNS performs DNS resolution for the given host and measures latency.
func ResolveDNS(ctx context.Context, host string) *DNSResult {
	start := time.Now()
	resolver := net.DefaultResolver

	addrs, err := resolver.LookupHost(ctx, host)
	duration := time.Since(start)

	return &DNSResult{
		Host:      host,
		Addresses: addrs,
		Duration:  duration,
		Error:     err,
	}
}

// TCPResult holds the outcome of a TCP connection attempt.
type TCPResult struct {
	Host     string
	Port     int
	Duration time.Duration
	Error    error
}

// DialTCP attempts a TCP connection to host:port and measures latency.
func DialTCP(ctx context.Context, host string, port int) *TCPResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	duration := time.Since(start)

	if conn != nil {
		conn.Close()
	}

	return &TCPResult{
		Host:     host,
		Port:     port,
		Duration: duration,
		Error:    err,
	}
}
