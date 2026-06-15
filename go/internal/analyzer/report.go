// report.go — formatted terminal output for protocol analysis results.
package analyzer

import (
	"fmt"
	"strings"
	"time"
)

// ANSI colour helpers
const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiBold   = "\033[1m"
	ansiGray   = "\033[90m"
)

func green(s string) string  { return ansiGreen + s + ansiReset }
func red(s string) string    { return ansiRed + s + ansiReset }
func yellow(s string) string { return ansiYellow + s + ansiReset }
func blue(s string) string   { return ansiBlue + s + ansiReset }
func cyan(s string) string   { return ansiCyan + s + ansiReset }
func bold(s string) string   { return ansiBold + s + ansiReset }
func gray(s string) string   { return ansiGray + s + ansiReset }

// PrintProtocol prints a formatted summary of one protocol analysis.
func PrintProtocol(p Protocol) {
	adv := Advice(p)

	// Domain header
	fmt.Printf("\n%s %s\n", bold("◆"), bold(p.Domain))
	fmt.Printf("  %s─────────────────────────────────────%s\n", ansiGray, ansiReset)

	if p.Error != "" {
		fmt.Printf("  %s Connection failed: %s\n", red("✗"), p.Error)
		fmt.Printf("  %s %s\n", yellow("→"), adv.Explanation)
		return
	}

	// TLS info
	tlsColour := green
	if p.TLSVersion == "TLS 1.0" || p.TLSVersion == "TLS 1.1" {
		tlsColour = yellow
	}
	fmt.Printf("  %-16s %s\n", gray("TLS:"), tlsColour(p.TLSVersion))
	fmt.Printf("  %-16s %s\n", gray("HTTP:"), blue(p.HTTPVersion))
	if p.ALPN != "" {
		fmt.Printf("  %-16s %s\n", gray("ALPN:"), gray(p.ALPN))
	}
	if p.CipherSuite != "" {
		short := p.CipherSuite
		if len(short) > 35 { short = short[:35] + "…" }
		fmt.Printf("  %-16s %s\n", gray("Cipher:"), gray(short))
	}
	fmt.Printf("  %-16s %dms\n", gray("Latency:"), p.Latency.Milliseconds())

	// Bypass advice
	fmt.Printf("  %s──%s %s\n", ansiGray, ansiReset, bold("FreedomNet"))
	if adv.TLSSplit {
		fmt.Printf("  %s TLS record split works\n", green("✓"))
	} else {
		fmt.Printf("  %s TLS record split N/A (%s)\n", yellow("?"), p.TLSVersion)
	}
	if adv.HTTPMangle {
		fmt.Printf("  %s HTTP header mangle applicable\n", green("✓"))
	}
	fmt.Printf("  %s DoH DNS recommended\n", green("✓"))
	if adv.H3Warning {
		fmt.Printf("  %s %s\n", yellow("⚠"), "HTTP/3 (QUIC/UDP) detected — bypass is TCP-only")
		fmt.Printf("      Fallback to HTTP/2 or HTTP/1.1 should still work.\n")
	}
}

// PrintSummaryTable prints a compact table for multiple analysis results.
func PrintSummaryTable(results []Protocol) {
	const (
		wDomain = 35
		wTLS    = 8
		wHTTP   = 8
		wLat    = 8
	)

	header := fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %s",
		wDomain, "Domain",
		wTLS, "TLS",
		wHTTP, "HTTP",
		wLat, "Latency",
		"Bypass")
	fmt.Printf("\n%s%s%s\n", ansiBold, header, ansiReset)
	fmt.Println(strings.Repeat("─", len(header)+10))

	for _, p := range results {
		domain := p.Domain
		if len(domain) > wDomain { domain = domain[:wDomain-1] + "…" }

		tls := p.TLSVersion
		if tls == "NONE" { tls = red("NONE") } else if tls == "TLS 1.3" { tls = green(tls) } else { tls = yellow(tls) }

		httpv := p.HTTPVersion
		if httpv == "HTTP/2" { httpv = green(httpv) } else { httpv = blue(httpv) }

		lat := fmt.Sprintf("%dms", p.Latency.Milliseconds())
		if p.Latency == 0 { lat = red("err") }

		adv := Advice(p)
		bypass := ""
		if adv.TLSSplit { bypass = green("✓ split") }
		if adv.H3Warning { bypass += yellow(" ⚠h3") }
		if p.Error != "" { bypass = red("✗ blocked") }

		fmt.Printf("%-*s  %-*s  %-*s  %-*s  %s\n",
			wDomain, domain,
			wTLS+10, tls, // +10 for ANSI escape overhead
			wHTTP+10, httpv,
			wLat, lat,
			bypass,
		)
	}
	fmt.Println()
}

// PrintReportStats summarises a batch of results.
func PrintReportStats(results []Protocol, elapsed time.Duration) {
	var ok, failed, tls12, tls13, h2, h3 int
	var totalLat time.Duration

	for _, p := range results {
		if p.Error != "" {
			failed++
		} else {
			ok++
			totalLat += p.Latency
			switch p.TLSVersion {
			case "TLS 1.3": tls13++
			case "TLS 1.2": tls12++
			}
			switch p.HTTPVersion {
			case "HTTP/2": h2++
			case "HTTP/3": h3++
			}
		}
	}

	avg := time.Duration(0)
	if ok > 0 { avg = totalLat / time.Duration(ok) }

	fmt.Printf("%s\n", strings.Repeat("─", 50))
	fmt.Printf("Analyzed: %d domains in %s\n", len(results), elapsed.Round(time.Millisecond))
	fmt.Printf("  %s: %d   %s: %d\n", green("✓ reachable"), ok, red("✗ blocked/error"), failed)
	fmt.Printf("  TLS 1.3: %d   TLS 1.2: %d\n", tls13, tls12)
	fmt.Printf("  HTTP/2: %d   HTTP/3: %d\n", h2, h3)
	if ok > 0 {
		fmt.Printf("  Avg latency: %dms\n", avg.Milliseconds())
	}
	fmt.Println()
}
