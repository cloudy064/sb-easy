// Package db opens the SQLite database and applies the shared SQL migrations,
// staying compatible with databases previously migrated by the Rust/sqlx backend.
package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cloudy064/sb-easy/migrations"
	_ "modernc.org/sqlite"
)

// Open opens (creating if needed) the SQLite DB, enables WAL + foreign keys, and
// runs any pending migrations.
func Open(path string) (*sql.DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", path)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	conn.SetMaxOpenConns(1) // sqlite: serialize writers; simplest correct default
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	if err := migrate(conn); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return conn, nil
}

// migrate applies migrations/NNN_*.sql not yet recorded. It seeds its tracking
// table from a pre-existing sqlx `_sqlx_migrations` so a Rust-created DB isn't
// re-migrated.
func migrate(conn *sql.DB) error {
	if _, err := conn.Exec(`CREATE TABLE IF NOT EXISTS go_schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		return err
	}

	applied := map[int]bool{}
	rows, err := conn.Query(`SELECT version FROM go_schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err == nil {
			applied[v] = true
		}
	}
	rows.Close()

	// Import already-applied versions from a legacy sqlx migration table.
	if tableExists(conn, "_sqlx_migrations") {
		r2, err := conn.Query(`SELECT version FROM _sqlx_migrations WHERE success = 1`)
		if err == nil {
			for r2.Next() {
				var v int
				if err := r2.Scan(&v); err == nil {
					applied[v] = true
				}
			}
			r2.Close()
		}
	}

	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return err
	}
	type mig struct {
		version int
		name    string
	}
	var migs []mig
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		num := e.Name()
		if i := strings.IndexByte(num, '_'); i >= 0 {
			num = num[:i]
		}
		v, err := strconv.Atoi(num)
		if err != nil {
			continue
		}
		migs = append(migs, mig{v, e.Name()})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })

	for _, m := range migs {
		if applied[m.version] {
			continue
		}
		body, err := migrations.FS.ReadFile(m.name)
		if err != nil {
			return err
		}
		if _, err := conn.Exec(string(body)); err != nil {
			return fmt.Errorf("apply %s: %w", m.name, err)
		}
		if _, err := conn.Exec(`INSERT OR IGNORE INTO go_schema_migrations (version) VALUES (?)`, m.version); err != nil {
			return err
		}
	}
	return nil
}

func tableExists(conn *sql.DB, name string) bool {
	var n int
	_ = conn.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n)
	return n > 0
}
