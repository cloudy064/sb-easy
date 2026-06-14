#!/bin/sh
set -e

# Ensure persistent data dir exists (DB + generated sing-box config live here).
mkdir -p /app/data

# Migrations run automatically on startup (embedded in the binary).
# Managed mode (default) supervises the bundled sing-box in process.
exec "$@"
