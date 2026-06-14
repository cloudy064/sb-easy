// Command sb-easy is the Go rewrite entrypoint: an all-in-one panel that
// embeds sing-box in process. `sb-easy agent` runs as a managed node.
package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cloudy064/sb-easy/internal/auth"
	"github.com/cloudy064/sb-easy/internal/config"
	"github.com/cloudy064/sb-easy/internal/db"
	"github.com/cloudy064/sb-easy/internal/server"
	"github.com/cloudy064/sb-easy/internal/singbox"
	"github.com/google/uuid"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "agent" {
		log.Fatal("agent mode is not ported to the Go backend yet")
	}

	cfg := config.Load()
	conn, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer conn.Close()
	log.Printf("database ready: %s", cfg.DBPath)

	if err := ensureAdmin(conn, cfg.AdminPassword); err != nil {
		log.Fatalf("seed admin: %v", err)
	}

	sb := singbox.New()
	defer sb.Close()

	srv := server.New(cfg, conn, sb)
	httpSrv := &http.Server{
		Addr:              cfg.BindAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("sb-easy (go) listening on http://%s", cfg.BindAddr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
	_ = context.Background()
}

// ensureAdmin creates a default admin user on an empty users table.
func ensureAdmin(conn *sql.DB, password string) error {
	var n int
	if err := conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = conn.Exec(
		"INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?,?,?,?,datetime('now'))",
		uuid.NewString(), "admin", hash, "admin",
	)
	if err == nil {
		log.Printf("seeded default admin user")
	}
	return err
}
