package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// TLSResult holds the outcome of a TLS handshake check.
type TLSResult struct {
	Host            string
	Port            int
	Version         uint16
	CipherSuite     uint16
	ServerName      string
	CertExpiry      time.Time
	CertIssuer      string
	CertSubject     string
	HandshakeDur    time.Duration
	Error           error
}

// TLSVersionString returns the human-readable TLS version name.
func TLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// CheckTLS performs a TLS handshake and inspects the certificate.
func CheckTLS(ctx context.Context, host string, port int) *TLSResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return &TLSResult{
			Host:  host,
			Port:  port,
			Error: fmt.Errorf("tcp dial failed: %w", err),
		}
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
	})
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return &TLSResult{
			Host:         host,
			Port:         port,
			HandshakeDur: time.Since(start),
			Error:        fmt.Errorf("tls handshake failed: %w", err),
		}
	}

	state := tlsConn.ConnectionState()
	result := &TLSResult{
		Host:         host,
		Port:         port,
		Version:      state.Version,
		CipherSuite:  state.CipherSuite,
		ServerName:   state.ServerName,
		HandshakeDur: time.Since(start),
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.CertExpiry = cert.NotAfter
		result.CertIssuer = cert.Issuer.String()
		result.CertSubject = cert.Subject.String()
	}

	return result
}
