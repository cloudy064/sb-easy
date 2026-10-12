#!/usr/bin/env bash
# Build this source tree, then update an existing Compose deployment in place.
# Usage: bash scripts/update-docker-subscriptions.sh /srv/sb-easy/docker-compose.yml
set -euo pipefail
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="${1:?Pass the existing deployment compose file, e.g. /srv/sb-easy/docker-compose.yml}"
compose_file="$(realpath -- "$compose_file")"
deployment_dir="$(dirname -- "$compose_file")"
service="${SB_EASY_SERVICE:-sb-easy}"
health_url="${SB_EASY_HEALTH_URL:-http://127.0.0.1:51821/api/health}"
command -v docker >/dev/null
command -v curl >/dev/null
docker compose version >/dev/null
compose=(docker compose --project-directory "$deployment_dir" -f "$compose_file")
"${compose[@]}" config --quiet
container="$("${compose[@]}" ps -q "$service")"
if [[ -z "$container" || "$container" == *$'\n'* ]]; then
  echo 'Expected exactly one existing sb-easy service. Check the compose path and SB_EASY_SERVICE.' >&2
  exit 1
fi
old_image="$(docker inspect --format '{{.Image}}' "$container")"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
image="sb-easy:subscriptions-$stamp"
rollback_image="sb-easy:before-subscriptions-$stamp"
docker image tag "$old_image" "$rollback_image"
docker build --tag "$image" "$source_dir"
override="$deployment_dir/sb-easy-release-$stamp.yml"
rollback_override="$deployment_dir/sb-easy-rollback-$stamp.yml"
printf 'services:\n  %s:\n    image: %s\n' "$service" "$image" > "$override"
printf 'services:\n  %s:\n    image: %s\n' "$service" "$rollback_image" > "$rollback_override"
rollback() {
  echo 'Update failed; restoring the previous image with the existing deployment settings.' >&2
  "${compose[@]}" -f "$rollback_override" up -d --no-deps --no-build "$service"
}
if ! "${compose[@]}" -f "$override" up -d --no-deps --no-build "$service"; then
  rollback
  exit 1
fi
for ((attempt=0; attempt<30; attempt++)); do
  if curl --fail --silent --max-time 3 "$health_url" >/dev/null; then
    echo "Updated successfully. Existing data, environment and network settings were retained."
    echo "Release override (use with the original compose file for future updates): $override"
    echo "Rollback override: $rollback_override"
    echo 'In Windows, sync the shared configuration to load subscription source names.'
    exit 0
  fi
  sleep 2
done
rollback
exit 1
