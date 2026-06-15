// compare.go — side-by-side direct vs proxy comparison.
package checker

import (
	"context"
	"sync"
	"time"
)

// Pair holds the direct and proxy results for one domain.
type Pair struct {
	Domain string
	Direct Result
	Proxy  Result
	// Gain is true if the site is blocked directly but reachable through proxy.
	Gain bool
}

// CompareConfig describes one comparison run.
type CompareConfig struct {
	Direct  Config
	Via     Config // ProxyAddr must be set
	Timeout time.Duration
}

// Compare probes each domain twice — once direct, once via proxy — and returns
// paired results plus a list of "gains" (sites the proxy unblocked).
func Compare(ctx context.Context, domains []string, cc CompareConfig) ([]Pair, []string) {
	pairs := make([]Pair, len(domains))
	var wg sync.WaitGroup
	sem := make(chan struct{}, cc.Direct.Concurrency)

	for i, d := range domains {
		wg.Add(1)
		go func(idx int, domain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var directRes, proxyRes Result
			var wg2 sync.WaitGroup
			wg2.Add(2)
			go func() {
				defer wg2.Done()
				directRes = probe(ctx, cc.Direct, domain)
			}()
			go func() {
				defer wg2.Done()
				proxyRes = probe(ctx, cc.Via, domain)
			}()
			wg2.Wait()

			pairs[idx] = Pair{
				Domain: domain,
				Direct: directRes,
				Proxy:  proxyRes,
				Gain:   directRes.Status != StatusOK && proxyRes.Status == StatusOK,
			}
		}(i, d)
	}

	wg.Wait()

	var gains []string
	for _, p := range pairs {
		if p.Gain {
			gains = append(gains, p.Domain)
		}
	}
	return pairs, gains
}
