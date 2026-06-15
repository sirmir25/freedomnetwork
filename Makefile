# FreedomNet — unified build
#
# Targets:
#   make           — build everything (proxy + VPN generator)
#   make proxy     — build Rust proxy + C++ core only
#   make vpn       — build D VPN generator only
#   make test      — run Rust unit tests
#   make check     — quick reachability test (requires fn-vpn)
#   make clean     — remove build artifacts
#   make install   — install binaries to /usr/local/bin

RUST_BIN    := target/release/fn
VPN_BIN     := vpngen/fn-vpn
D_SOURCES   := $(wildcard vpngen/source/*.d)
LDC         := $(shell command -v ldc2 2>/dev/null || command -v dmd 2>/dev/null)

.PHONY: all proxy vpn test check clean install

all: proxy vpn

# ── Rust + C++ ───────────────────────────────────────────────────────────────
proxy:
	cargo build --release

# ── D VPN generator ──────────────────────────────────────────────────────────
vpn: $(VPN_BIN)

$(VPN_BIN): $(D_SOURCES)
ifndef LDC
	$(error "D compiler not found. Install with: brew install ldc  or  https://dlang.org")
endif
	$(LDC) -O2 -of=$@ $(D_SOURCES)

# ── Tests ────────────────────────────────────────────────────────────────────
test:
	cargo test

# ── Quick site check (run after 'make vpn') ──────────────────────────────────
check: vpn
	$(VPN_BIN) check google.com youtube.com bbc.com rutracker.org

# ── Install ──────────────────────────────────────────────────────────────────
install: all
	@echo "Installing to /usr/local/bin..."
	install -m 755 $(RUST_BIN) /usr/local/bin/fn
	install -m 755 $(VPN_BIN)  /usr/local/bin/fn-vpn
	@echo "Done. Run:  fn  to start the proxy."

# ── Clean ────────────────────────────────────────────────────────────────────
clean:
	cargo clean
	rm -f $(VPN_BIN)
