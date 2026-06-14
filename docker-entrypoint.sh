#!/bin/sh
set -e

# Ensure runtime dirs exist: DB + generated config, and sing-box's cache dir
# (configs commonly point cache_file at /var/lib/sing-box).
mkdir -p /app/data /var/lib/sing-box

# Migrations run automatically on startup (embedded in the binary).
# Managed mode (default) supervises the bundled sing-box in process.
exec "$@"
