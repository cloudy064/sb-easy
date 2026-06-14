// Package server wires the HTTP API and static frontend.
package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudy064/sb-easy/internal/auth"
	"github.com/cloudy064/sb-easy/internal/config"
	"github.com/cloudy064/sb-easy/internal/singbox"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	cfg config.Config
	db  *sql.DB
	sb  *singbox.Manager
}

func New(cfg config.Config, db *sql.DB, sb *singbox.Manager) *Server {
	return &Server{cfg: cfg, db: db, sb: sb}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	r.Route("/api", func(r chi.Router) {
		r.Get("/system/status", s.status)
		r.Post("/auth/login", s.login)

		// Unknown /api/* → 404 JSON (never fall through to the SPA, which would
		// feed HTML to the frontend and crash it — a bug we hit in the Rust app).
		r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "Not found"})
		})
	})

	// Static frontend + SPA fallback.
	r.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.Dir(filepath.Join(s.cfg.FrontendDir, "assets")))))
	r.NotFound(s.spa)
	return r
}

func (s *Server) spa(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Not found"})
		return
	}
	index := filepath.Join(s.cfg.FrontendDir, "index.html")
	if _, err := os.Stat(index); err != nil {
		http.Error(w, "frontend not built", http.StatusInternalServerError)
		return
	}
	http.ServeFile(w, r, index)
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	count := func(table string) int64 {
		var n int64
		_ = s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
		return n
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "running",
		"backend": "go",
		"wireguard": map[string]any{"peer_count": count("wireguard_peers")},
		"sing_box":  map[string]any{"node_count": count("proxy_nodes"), "embedded_running": s.sb.Running()},
		"hosts":     map[string]any{"count": count("hosts")},
		"subscriptions": map[string]any{"count": count("subscriptions")},
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	var hash, role string
	err := s.db.QueryRow("SELECT password_hash, role FROM users WHERE username = ?", req.Username).Scan(&hash, &role)
	if err != nil || !auth.VerifyPassword(hash, req.Password) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	token, err := auth.IssueToken(s.cfg.JWTSecret, req.Username, role, 24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "username": req.Username, "role": role})
}
