#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

container_name="${CONTAINER_NAME:-sb-easy-agent}"
image_tag="${IMAGE_TAG:-sb-easy:unified-agent-$(date +%Y%m%d-%H%M%S)}"
dockerfile="${DOCKERFILE:-c/Dockerfile.unified}"
skip_build="${SKIP_BUILD:-0}"
health_timeout="${HEALTH_TIMEOUT:-60}"
stop_timeout="${STOP_TIMEOUT:-8}"
test_url="${TEST_URL:-https://www.google.com/generate_204}"
repo_dir="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
timestamp="$(date +%Y%m%d-%H%M%S)"
rollback_name="${container_name}-rollback-${timestamp}"
failed_name="${container_name}-failed-${timestamp}"

case "$health_timeout" in
  ''|*[!0-9]*)
    echo "HEALTH_TIMEOUT and STOP_TIMEOUT must be non-negative integers" >&2
    exit 2
    ;;
esac
case "$stop_timeout" in
  ''|*[!0-9]*)
    echo "HEALTH_TIMEOUT and STOP_TIMEOUT must be non-negative integers" >&2
    exit 2
    ;;
esac

docker inspect "$container_name" >/dev/null
data_source="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Source}}{{end}}{{end}}' "$container_name")"
if [[ -z "$data_source" || ! -d "$data_source" ]]; then
  echo "Could not resolve the existing /app/data bind mount" >&2
  exit 3
fi

env_file="$(mktemp /tmp/sb-easy-agent-env.XXXXXX)"
backup_dir="$(mktemp -d /tmp/sb-easy-agent-backup.XXXXXX)"
docker inspect "$container_name" >"$backup_dir/container.json"
cutover_started=false
deployment_complete=false
rollback_done=false
data_backup_ready=false

rollback() {
  if [[ "$rollback_done" == true ]]; then
    return
  fi
  rollback_done=true
  echo "Candidate failed; restoring the previous container" >&2
  if docker inspect "$rollback_name" >/dev/null 2>&1; then
    if docker inspect "$container_name" >/dev/null 2>&1; then
      docker update --restart=no "$container_name" >/dev/null 2>&1 || true
      docker stop -t 3 "$container_name" >/dev/null 2>&1 || true
      docker rename "$container_name" "$failed_name" >/dev/null 2>&1 || true
    fi
    docker rename "$rollback_name" "$container_name" >/dev/null 2>&1 || true
  fi
  if [[ "$data_backup_ready" == true ]]; then
    docker run --rm --network none --entrypoint tar \
      -v "$data_source:/restore" -v "$backup_dir:/backup:ro" "$image_tag" \
      -xzf /backup/data.tar.gz -C /restore || echo "Data restore failed: $backup_dir" >&2
  fi
  docker update --restart=unless-stopped "$container_name" >/dev/null 2>&1 || true
  docker start "$container_name" >/dev/null 2>&1 || true
}

finish() {
  result=$?
  trap - EXIT INT TERM
  rm -f "$env_file"
  if [[ "$cutover_started" == true && "$deployment_complete" != true ]]; then
    rollback
  fi
  exit "$result"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 600 "$env_file"

if [[ "$skip_build" == 0 ]]; then
  echo "Building $image_tag while $container_name remains online"
  docker build -f "$repo_dir/$dockerfile" -t "$image_tag" "$repo_dir"
elif [[ "$skip_build" != 1 ]]; then
  echo "SKIP_BUILD must be 0 or 1" >&2
  exit 2
fi
docker run --rm --entrypoint /bin/sh "$image_tag" -ec \
  'test -d /var/lib/sing-box && test -x /usr/local/bin/sb-easy && command -v curl >/dev/null'

healthcheck="$(docker image inspect "$image_tag" --format '{{json .Config.Healthcheck}}')"
if [[ "$healthcheck" == "null" ]]; then
  echo "Refusing cutover: the candidate image has no healthcheck" >&2
  exit 4
fi

docker inspect "$container_name" --format '{{range .Config.Env}}{{println .}}{{end}}' >"$env_file"
docker update --restart=no "$container_name" >/dev/null
cutover_started=true
docker stop -t "$stop_timeout" "$container_name" >/dev/null
docker run --rm --network none --entrypoint tar \
  -v "$data_source:/source:ro" "$image_tag" -C /source -czf - . >"$backup_dir/data.tar.gz"
data_backup_ready=true
docker rename "$container_name" "$rollback_name"

if ! docker run -d \
  --name "$container_name" \
  --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun:rwm \
  --env-file "$env_file" \
  -v "$data_source:/app/data" \
  "$image_tag" >/dev/null; then
  exit 5
fi

deadline=$((SECONDS + health_timeout))
candidate_healthy=false
while ((SECONDS < deadline)); do
  state="$(docker inspect "$container_name" --format '{{.State.Status}}')"
  health="$(docker inspect "$container_name" --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}')"
  if [[ "$state" == "running" && "$health" == "healthy" ]]; then
    candidate_healthy=true
    break
  fi
  if [[ "$state" != "running" || "$health" == "unhealthy" ]]; then
    break
  fi
  sleep 1
done

if [[ "$candidate_healthy" != true ]]; then
  docker logs --tail 100 "$container_name" >&2 || true
  exit 6
fi

test_status="$(curl -sS --max-time 15 -x http://127.0.0.1:7890 \
  -o /dev/null -w '%{http_code}' "$test_url" || true)"
if [[ "$test_status" != "204" ]]; then
  echo "Proxy test failed: $test_url returned $test_status" >&2
  exit 7
fi

deployment_complete=true
echo "Deployment healthy: $container_name -> $image_tag"
echo "Rollback container retained as: $rollback_name"
echo "Container settings and data backup: $backup_dir"
