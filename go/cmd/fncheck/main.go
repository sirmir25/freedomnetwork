// fncheck — FreedomNet companion site reachability checker.
//
// Tests domains directly and optionally through a FreedomNet SOCKS5 proxy,
// showing what is blocked and what gets unblocked by the proxy.
//
// Usage:
//
//	fncheck check google.com youtube.com bbc.com
//	fncheck check --proxy 127.0.0.1:1080 --compare google.com bbc.com
//	fncheck check --file lists/gfw.txt --proxy 127.0.0.1:1080 --compare
//	fncheck ping  127.0.0.1:1080
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/sirmir25/freedomnetwork/go/internal/checker"
	iproxy "github.com/sirmir25/freedomnetwork/go/internal/proxy"
)

var (
	flagProxy       string
	flagTimeout     int
	flagConcurrency int
	flagFile        string
	flagCompare     bool
	flagHTTPS       bool
	flagJSON        bool
)

func main() {
	root := &cobra.Command{
		Use:   "fncheck",
		Short: "FreedomNet site reachability checker",
		Long: `fncheck tests whether domains are reachable directly and/or through
the FreedomNet DPI-bypass proxy.  Useful for diagnosing which sites are
blocked before starting the proxy, and verifying that the proxy works.`,
	}

	checkCmd := &cobra.Command{
		Use:   "check [domain...]",
		Short: "Check TCP reachability of one or more domains",
		Example: `  fncheck check google.com youtube.com bbc.com
  fncheck check --proxy 127.0.0.1:1080 --compare google.com bbc.com
  fncheck check --file lists/gfw.txt --compare --proxy 127.0.0.1:1080`,
		RunE: runCheck,
	}
	checkCmd.Flags().StringVar(&flagProxy, "proxy", "", "FreedomNet SOCKS5 address (e.g. 127.0.0.1:1080)")
	checkCmd.Flags().IntVar(&flagTimeout, "timeout", 4000, "Per-probe timeout in milliseconds")
	checkCmd.Flags().IntVar(&flagConcurrency, "concurrency", 20, "Number of parallel probes")
	checkCmd.Flags().StringVar(&flagFile, "file", "", "File with one domain per line")
	checkCmd.Flags().BoolVar(&flagCompare, "compare", false, "Compare direct vs proxy (requires --proxy)")
	checkCmd.Flags().BoolVar(&flagHTTPS, "https", false, "Also perform a TLS handshake after TCP connect")
	checkCmd.Flags().BoolVar(&flagJSON, "json", false, "Output results as JSON")

	pingCmd := &cobra.Command{
		Use:   "ping [proxy-addr]",
		Short: "Check that FreedomNet proxy is alive",
		Args:  cobra.ExactArgs(1),
		RunE:  runPing,
	}

	root.AddCommand(checkCmd, pingCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ── check ─────────────────────────────────────────────────────────────────────

func runCheck(cmd *cobra.Command, args []string) error {
	domains := args

	if flagFile != "" {
		extra, err := checker.LoadDomains(flagFile)
		if err != nil {
			return fmt.Errorf("loading %s: %w", flagFile, err)
		}
		domains = append(domains, extra...)
	}

	if len(domains) == 0 {
		return fmt.Errorf("no domains specified (pass as args or use --file)")
	}

	// Deduplicate
	seen := make(map[string]bool)
	uniq := domains[:0]
	for _, d := range domains {
		d = strings.TrimSpace(strings.ToLower(d))
		if d != "" && !seen[d] {
			seen[d] = true
			uniq = append(uniq, d)
		}
	}
	domains = uniq

	directCfg := checker.Config{
		Port:        443,
		TimeoutMs:   flagTimeout,
		Concurrency: flagConcurrency,
		HTTPS:       flagHTTPS,
	}
	proxyCfg := directCfg
	proxyCfg.ProxyAddr = flagProxy

	if flagCompare && flagProxy != "" {
		return runCompare(domains, directCfg, proxyCfg)
	}

	// Simple direct (or proxy-only) probe
	cfg := directCfg
	if flagProxy != "" {
		cfg = proxyCfg
		label := color.New(color.FgCyan).Sprint("via proxy " + flagProxy)
		fmt.Printf("\nChecking %d domain(s) %s...\n\n", len(domains), label)
	} else {
		fmt.Printf("\nChecking %d domain(s) directly...\n\n", len(domains))
	}

	ctx := context.Background()
	results := checker.Probe(ctx, domains, cfg)

	printResults(results)

	sum := checker.Summarise(results)
	fmt.Printf("\n%s  %d/%d reachable",
		color.GreenString("✓"),
		sum.OK, sum.Total)
	if sum.Blocked+sum.DNS > 0 {
		fmt.Printf("   %s  %d blocked",
			color.RedString("✗"),
			sum.Blocked+sum.DNS)
	}
	if sum.OK > 0 {
		fmt.Printf("   latency p50=%dms p95=%dms", sum.P50ms, sum.P95ms)
	}
	fmt.Println()

	if sum.Blocked+sum.DNS > 0 && flagProxy == "" {
		fmt.Println()
		fmt.Println(color.YellowString("Tip:") + " run FreedomNet proxy then re-check with --proxy 127.0.0.1:1080 --compare")
	}
	return nil
}

func printResults(results []checker.Result) {
	okMark  := color.GreenString("✓")
	badMark := color.RedString("✗")
	for _, r := range results {
		var mark, note string
		if r.Status == checker.StatusOK {
			mark = okMark
			note = color.GreenString("reachable")
		} else {
			mark = badMark
			note = color.RedString(r.Status.String())
		}
		fmt.Printf("  %s  %-40s  %4dms  %s\n",
			mark, r.Domain, r.Latency.Milliseconds(), note)
	}
}

func runCompare(domains []string, directCfg, proxyCfg checker.Config) error {
	fmt.Printf("\nComparing direct vs %s for %d domain(s)...\n\n",
		color.CyanString("proxy "+flagProxy), len(domains))

	cc := checker.CompareConfig{
		Direct:  directCfg,
		Via:     proxyCfg,
		Timeout: time.Duration(flagTimeout) * time.Millisecond,
	}

	ctx := context.Background()
	pairs, gains := checker.Compare(ctx, domains, cc)

	w1 := color.New(color.FgWhite, color.Bold)
	for _, p := range pairs {
		var dMark, pMark string
		if p.Direct.Status == checker.StatusOK {
			dMark = color.GreenString("✓")
		} else {
			dMark = color.RedString("✗")
		}
		if p.Proxy.Status == checker.StatusOK {
			pMark = color.GreenString("✓")
		} else {
			pMark = color.RedString("✗")
		}

		extra := ""
		if p.Gain {
			extra = color.MagentaString(" ← UNBLOCKED")
		}

		w1.Printf("  %-40s", p.Domain)
		fmt.Printf("  direct: %s  proxy: %s%s\n", dMark, pMark, extra)
	}

	fmt.Printf("\n%s\n", strings.Repeat("─", 60))
	fmt.Printf("Sites unblocked by FreedomNet: %s\n",
		color.MagentaString("%d / %d", len(gains), len(pairs)))

	if len(gains) > 0 {
		fmt.Println()
		for _, g := range gains {
			fmt.Printf("  %s %s\n", color.MagentaString("●"), g)
		}
	}
	fmt.Println()
	return nil
}

// ── ping ──────────────────────────────────────────────────────────────────────

func runPing(cmd *cobra.Command, args []string) error {
	addr := args[0]
	fmt.Printf("Pinging FreedomNet proxy at %s ... ", color.CyanString(addr))

	alive := iproxy.IsAlive(addr, 3*time.Second)
	if alive {
		fmt.Println(color.GreenString("OK — proxy is up"))
	} else {
		fmt.Println(color.RedString("FAILED — proxy not responding"))
		fmt.Println("Start it with:  fn  (or  ./target/release/fn)")
		return fmt.Errorf("proxy not alive")
	}
	return nil
}
