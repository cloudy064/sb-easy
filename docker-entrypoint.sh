#!/bin/sh
set -e

# Run database migrations
echo "sb-easy entrypoint: running migrations..."
# Migrations are embedded in the binary via sqlx::migrate!
# They run automatically when the app starts.

# Start the application
exec "$@"
