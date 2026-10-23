#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
output_dir=${1:-"$repo_dir/build/linux-package"}
mkdir -p -- "$output_dir"
# A new build container only: no host network, ports, production volumes or services.
docker buildx build --file "$repo_dir/linux/packaging/Dockerfile" --target package \
    --output "type=local,dest=$output_dir" "$repo_dir"
