// Package checker performs concurrent TCP/TLS reachability probes.
// It can test sites both directly and through a SOCKS5 proxy so you
// can compare what is blocked vs what FreedomNet unblocks.
package checker

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// Status of a single probe.
type Status int

const (
	StatusOK      Status = iota // TCP connect succeeded
	StatusBlocked               // connect timed out or refused
	StatusDNS                   // DNS resolution failed
	StatusError                 // other error
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusBlocked:
		return "BLOCKED"
	case StatusDNS:
		return "DNS-BLOCKED"
	default:
		return "ERROR"
	}
}

// Result of probing one domain.
type Result struct {
	Domain   string
	Port     int
	Status   Status
	Latency  time.Duration
	Error    string
	ProxyURL string // empty = direct
}

// Config controls how probes are run.
type Config struct {
	Port        int
	TimeoutMs   int
	Concurrency int
	ProxyAddr   string // e.g. "127.0.0.1:1080" for SOCKS5; empty = direct
	HTTPS       bool   // attempt a TLS handshake after TCP connect
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Port:        443,
		TimeoutMs:   4000,
		Concurrency: 20,
		HTTPS:       false,
	}
}

func dial(ctx context.Context, cfg Config, domain string) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", domain, cfg.Port)
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond

	if cfg.ProxyAddr != "" {
		dialer, err := proxy.SOCKS5("tcp", cfg.ProxyAddr, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("SOCKS5 dialer: %w", err)
		}
		return dialer.Dial("tcp", addr)
	}

	nd := &net.Dialer{Timeout: timeout}
	return nd.DialContext(ctx, "tcp", addr)
}

func probe(ctx context.Context, cfg Config, domain string) Result {
	start := time.Now()
	r := Result{
		Domain:   domain,
		Port:     cfg.Port,
		ProxyURL: cfg.ProxyAddr,
	}

	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dial(ctx2, cfg, domain)
	r.Latency = time.Since(start)

	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "no such host") || strings.Contains(msg, "lookup") {
			r.Status = StatusDNS
		} else if r.Latency >= timeout-50*time.Millisecond {
			r.Status = StatusBlocked
		} else {
			r.Status = StatusBlocked
		}
		r.Error = msg
		return r
	}
	defer conn.Close()

	if cfg.HTTPS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         domain,
			InsecureSkipVerify: false,
		})
		tlsConn.SetDeadline(time.Now().Add(timeout))
		if err := tlsConn.Handshake(); err != nil {
			r.Status = StatusBlocked
			r.Error = "TLS: " + err.Error()
			return r
		}
	}

	r.Status = StatusOK
	return r
}

// Probe tests a list of domains concurrently.
func Probe(ctx context.Context, domains []string, cfg Config) []Result {
	sem := make(chan struct{}, cfg.Concurrency)
	results := make([]Result, len(domains))
	var wg sync.WaitGroup

	for i, d := range domains {
		wg.Add(1)
		go func(idx int, domain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = probe(ctx, cfg, domain)
		}(i, d)
	}

	wg.Wait()
	return results
}

// LoadDomains reads a domain list file (one per line, # for comments).
func LoadDomains(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// Summary holds aggregated probe statistics.
type Summary struct {
	Total    int
	OK       int
	Blocked  int
	DNS      int
	Errors   int
	P50ms    int64
	P95ms    int64
	MaxMs    int64
}

// Summarise computes summary statistics from a slice of results.
func Summarise(results []Result) Summary {
	s := Summary{Total: len(results)}
	var latencies []int64
	for _, r := range results {
		switch r.Status {
		case StatusOK:
			s.OK++
			latencies = append(latencies, r.Latency.Milliseconds())
		case StatusBlocked:
			s.Blocked++
		case StatusDNS:
			s.DNS++
		default:
			s.Errors++
		}
	}
	if len(latencies) == 0 {
		return s
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	s.P50ms = latencies[len(latencies)/2]
	s.P95ms = latencies[int(math.Ceil(float64(len(latencies))*0.95))-1]
	s.MaxMs = latencies[len(latencies)-1]
	return s
}

// BuildHTTPClient returns an *http.Client that routes through the proxy if set.
func BuildHTTPClient(cfg Config) *http.Client {
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
		TLSHandshakeTimeout: timeout,
	}

	if cfg.ProxyAddr != "" {
		dialer, err := proxy.SOCKS5("tcp", cfg.ProxyAddr, nil, proxy.Direct)
		if err == nil {
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
	}

	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// HTTPProbe sends an HTTP GET and returns the status code (0 on error).
func HTTPProbe(ctx context.Context, cfg Config, domain string) (int, time.Duration, error) {
	client := BuildHTTPClient(cfg)
	scheme := "http"
	if cfg.HTTPS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	start := time.Now()
	resp, err := client.Do(req)
	lat := time.Since(start)
	if err != nil {
		return 0, lat, err
	}
	resp.Body.Close()
	return resp.StatusCode, lat, nil
}
