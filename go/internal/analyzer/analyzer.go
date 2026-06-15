// Package analyzer detects the protocol used by a connection and
// reports whether FreedomNet's bypass techniques apply.
//
// Detects:
//   - TLS version (1.0 / 1.1 / 1.2 / 1.3)
//   - HTTP version (HTTP/1.1 / HTTP/2 via ALPN / HTTP/3 via Alt-Svc header)
//   - Whether the site supports ECH (Encrypted Client Hello)
//   - Whether QUIC/HTTP3 is advertised (bypass techniques don't apply to UDP)
package analyzer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Protocol describes the connection characteristics of a site.
type Protocol struct {
	Domain      string
	Port        int
	TLSVersion  string // "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "NONE"
	HTTPVersion string // "HTTP/1.1", "HTTP/2", "HTTP/3", "unknown"
	ALPN        string // raw negotiated ALPN value
	SupportsECH bool
	SupportsH3  bool // HTTP/3 advertised via Alt-Svc
	Latency     time.Duration
	CipherSuite string
	SNI         string
	Error       string
}

// BypassAdvice explains which FreedomNet techniques apply.
type BypassAdvice struct {
	TLSSplit     bool   // TLS record fragmentation works
	HTTPMangle   bool   // HTTP header mangling works
	DoHRequired  bool   // DNS-over-HTTPS likely needed
	H3Warning    bool   // HTTP/3 (QUIC) detected — UDP bypass not supported
	Explanation  string
}

// Analyze performs a TLS handshake to detect protocol details.
func Analyze(ctx context.Context, domain string, port int, timeout time.Duration) Protocol {
	p := Protocol{Domain: domain, Port: port, SNI: domain}
	start := time.Now()

	addr := fmt.Sprintf("%s:%d", domain, port)
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		p.Error = fmt.Sprintf("TCP connect: %v", err)
		p.TLSVersion = "NONE"
		return p
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: false,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		p.Error = fmt.Sprintf("TLS handshake: %v", err)
		p.TLSVersion = "NONE"
		p.Latency = time.Since(start)
		return p
	}
	p.Latency = time.Since(start)

	state := tlsConn.ConnectionState()
	p.TLSVersion  = tlsVersionName(state.Version)
	p.ALPN        = state.NegotiatedProtocol
	p.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	switch state.NegotiatedProtocol {
	case "h2":
		p.HTTPVersion = "HTTP/2"
	case "http/1.1", "":
		p.HTTPVersion = "HTTP/1.1"
	case "h3":
		p.HTTPVersion = "HTTP/3"
		p.SupportsH3 = true
	default:
		p.HTTPVersion = "HTTP/1.1"
	}

	return p
}

// AnalyzeHTTP sends a GET request and checks the Alt-Svc header for H3 / ECH hints.
func AnalyzeHTTP(ctx context.Context, domain string, timeout time.Duration) (string, bool) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domain+"/", nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; fncheck/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	altSvc := resp.Header.Get("Alt-Svc")
	supportsH3 := strings.Contains(altSvc, "h3") || strings.Contains(altSvc, "quic")
	return resp.Proto, supportsH3
}

// Advice generates bypass recommendations based on a Protocol analysis.
func Advice(p Protocol) BypassAdvice {
	a := BypassAdvice{}

	if p.Error != "" {
		a.DoHRequired = true
		a.Explanation = fmt.Sprintf(
			"Connection failed (%s). DNS blocking likely — DoH should help.",
			p.Error,
		)
		return a
	}

	// TLS split works for TLS 1.2 and 1.3 (ClientHello structure is compatible)
	a.TLSSplit = p.TLSVersion == "TLS 1.2" || p.TLSVersion == "TLS 1.3"

	// HTTP mangle works for HTTP/1.1 plaintext (rarely seen on port 443)
	a.HTTPMangle = p.HTTPVersion == "HTTP/1.1"

	// Always recommend DoH (ISP DNS may be poisoned)
	a.DoHRequired = true

	if p.SupportsH3 {
		a.H3Warning = true
	}

	var parts []string
	if a.TLSSplit {
		parts = append(parts, fmt.Sprintf("TLS record split (%s)", p.TLSVersion))
	}
	if a.HTTPMangle {
		parts = append(parts, "HTTP header mangling")
	}
	parts = append(parts, "DoH DNS")
	if a.H3Warning {
		parts = append(parts, "⚠ HTTP/3 (UDP) detected — TCP bypass only")
	}

	a.Explanation = strings.Join(parts, "; ")
	return a
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10: return "TLS 1.0"
	case tls.VersionTLS11: return "TLS 1.1"
	case tls.VersionTLS12: return "TLS 1.2"
	case tls.VersionTLS13: return "TLS 1.3"
	default:               return fmt.Sprintf("TLS 0x%04x", v)
	}
}

// BatchAnalyze analyzes multiple domains concurrently.
func BatchAnalyze(ctx context.Context, domains []string, port int, timeout time.Duration, concurrency int) []Protocol {
	type job struct{ idx int; domain string }
	jobs := make(chan job, len(domains))
	for i, d := range domains { jobs <- job{i, d} }
	close(jobs)

	results := make([]Protocol, len(domains))
	done := make(chan struct{}, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			for j := range jobs {
				results[j.idx] = Analyze(ctx, j.domain, port, timeout)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < concurrency; i++ { <-done }
	return results
}
