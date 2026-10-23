#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
build_dir=${1:-"$repo_dir/build/linux-desktop"}
core_dir=${2:-"$repo_dir/build/linux-core"}
"$repo_dir/linux/scripts/prepare-core.sh" "$core_dir"
core_dir=$(cd -- "$core_dir" && pwd)
cmake -S "$repo_dir/linux" -B "$build_dir" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DSB_EASY_SINGBOX_BRIDGE_LIBRARY="$core_dir/libsb_easy_singbox.a" \
    -DSB_EASY_SINGBOX_BRIDGE_INCLUDE_DIR="$core_dir" "${@:3}"
cmake --build "$build_dir" --parallel "${SBL_BUILD_JOBS:-4}" --target \
    sb-easy-desktop sb-easy-tunnel linux_core_test linux_service_test linux_keyring_test \
    linux_system_proxy_test linux_controller_test linux_tun_test linux_ui_smoke
