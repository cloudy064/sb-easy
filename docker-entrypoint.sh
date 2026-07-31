#!/bin/sh
set -e

# Ensure runtime dirs exist: DB + generated config, and sing-box's cache dir
# (configs commonly point cache_file at /var/lib/sing-box).
mkdir -p /app/data /var/lib/sing-box

# Preserve the former image's `sb-easy agent` invocation while dispatching to
# the dedicated C++ polling-agent executable.
if [ "${1:-}" = "sb-easy" ] && [ "${2:-}" = "agent" ]; then
    shift 2
    exec sb-easy-agent "$@"
fi

# The server reads DATABASE_URL/MIGRATIONS_DIR itself and runs migrations before
# listening. Managed mode supervises the bundled sing-box process.
exec "$@"
