// Package migrations embeds the shared SQL migration files so the Go binary can
// run them. The same .sql files are used by the (legacy) Rust backend via sqlx.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
