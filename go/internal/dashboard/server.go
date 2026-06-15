// Package dashboard serves a real-time HTML stats page for FreedomNet.
//
// Endpoints:
//   GET /          — HTML dashboard page
//   GET /api/stats — JSON snapshot of current stats
//   GET /api/log   — last N log lines as JSON
//   GET /health    — 200 OK
package dashboard

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Stats holds current runtime metrics.  All fields must be safe to serialise.
type Stats struct {
	Uptime           string  `json:"uptime"`
	TotalConnections uint64  `json:"total_connections"`
	ActiveConnections int64  `json:"active_connections"`
	BytesUp          uint64  `json:"bytes_up"`
	BytesDown        uint64  `json:"bytes_down"`
	BytesUpHuman     string  `json:"bytes_up_human"`
	BytesDownHuman   string  `json:"bytes_down_human"`
	TLSSplits        uint64  `json:"tls_splits"`
	DoHHitRate       float64 `json:"doh_hit_rate"`
	StartedAt        string  `json:"started_at"`
}

// LogEntry is a single timestamped message shown in the dashboard log pane.
type LogEntry struct {
	At      string `json:"at"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// Provider is the interface the dashboard calls to get live data.
type Provider interface {
	Snapshot() Stats
}

// Server is the HTTP dashboard server.
type Server struct {
	provider Provider
	addr     string
	logMu    sync.Mutex
	logLines []LogEntry
	maxLog   int
}

// New creates a new dashboard Server.
func New(addr string, provider Provider) *Server {
	return &Server{
		addr:     addr,
		provider: provider,
		maxLog:   200,
	}
}

// Log appends a log message that will appear in the dashboard.
func (s *Server) Log(level, msg string) {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	s.logLines = append(s.logLines, LogEntry{
		At:      time.Now().Format("15:04:05"),
		Level:   level,
		Message: msg,
	})
	if len(s.logLines) > s.maxLog {
		s.logLines = s.logLines[len(s.logLines)-s.maxLog:]
	}
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/log", s.handleLog)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	})

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	log.Printf("[dashboard] listening on http://%s", s.addr)
	return http.Serve(ln, mux)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	snap := s.provider.Snapshot()
	json.NewEncoder(w).Encode(snap)
}

func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	s.logMu.Lock()
	lines := make([]LogEntry, len(s.logLines))
	copy(lines, s.logLines)
	s.logMu.Unlock()
	json.NewEncoder(w).Encode(lines)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, dashboardHTML)
}

func fmtBytes(b uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
