#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
rust_bin=${SB_EASY_RUST_BIN:-"$repo_dir/target/debug/sb-easy"}
cpp_bin=${SB_EASY_CPP_BIN:-"$repo_dir/build/cpp-gcc/sb-easy-cpp-server"}
rust_port=${SB_EASY_RUST_PARITY_PORT:-32181}
cpp_port=${SB_EASY_CPP_PARITY_PORT:-32182}
jwt_secret=parity-jwt-secret-with-a-stable-value
admin_password=parity-admin-password
work_dir=$(mktemp -d)
database="$work_dir/parity.db"
active_pid=

cleanup() {
    if [ -n "$active_pid" ]; then
        kill -TERM "$active_pid" 2>/dev/null || true
        wait "$active_pid" 2>/dev/null || true
    fi
    rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required tool is missing: $1" >&2
        exit 2
    fi
}

wait_ready() {
    base_url=$1
    log_file=$2
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        if curl -fsS "$base_url/api/system/status" >/dev/null 2>&1; then
            return
        fi
        attempt=$((attempt + 1))
        sleep 0.1
    done
    echo "backend did not become ready: $base_url" >&2
    tail -n 100 "$log_file" >&2 || true
    exit 1
}

stop_backend() {
    kill -TERM "$active_pid"
    wait "$active_pid"
    active_pid=
}

login_token() {
    base_url=$1
    curl -fsS \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"admin\",\"password\":\"$admin_password\"}" \
        "$base_url/api/auth/login" |
        jq -er '.token'
}

require_tool curl
require_tool jq
if [ ! -x "$rust_bin" ]; then
    echo "Rust backend not found at $rust_bin; run: cargo build -p sb-easy" >&2
    exit 2
fi
if [ ! -x "$cpp_bin" ]; then
    echo "C++ backend not found at $cpp_bin; build the sb-easy-cpp-server target" >&2
    exit 2
fi

rust_url="http://127.0.0.1:$rust_port"
(
    cd "$repo_dir"
    exec env \
        BIND_ADDR="127.0.0.1:$rust_port" \
        DATABASE_URL="sqlite:$database?mode=rwc" \
        JWT_SECRET="$jwt_secret" \
        ADMIN_PASSWORD="$admin_password" \
        WG_ENABLED=false \
        SINGBOX_MANAGED=false \
        SELF_SINGBOX_CONFIG_PATH= \
        CONFIG_HASH_SEED=parity-config-seed \
        RUST_LOG=warn \
        "$rust_bin"
) >"$work_dir/rust.log" 2>&1 &
active_pid=$!
wait_ready "$rust_url" "$work_dir/rust.log"
rust_token=$(login_token "$rust_url")

curl -fsS \
    -H "Authorization: Bearer $rust_token" \
    -H 'Content-Type: application/json' \
    -d '{"tag":"alpha-ss","node_type":"shadowsocks","server":"ss.example.com","server_port":8388,"protocol_config":{"method":"aes-256-gcm","password":"secret"}}' \
    "$rust_url/api/proxy/nodes" >/dev/null
curl -fsS \
    -H "Authorization: Bearer $rust_token" \
    -H 'Content-Type: application/json' \
    -d '{"tag":"beta-vless","node_type":"vless","server":"vless.example.com","server_port":443,"protocol_config":{"uuid":"00000000-0000-0000-0000-000000000001","flow":"","packet_encoding":"xudp","tls":{"enabled":true,"server_name":"vless.example.com"}}}' \
    "$rust_url/api/proxy/nodes" >/dev/null
curl -fsS \
    -H "Authorization: Bearer $rust_token" \
    "$rust_url/api/hosts/self/config" |
    jq --sort-keys . >"$work_dir/rust-config.json"
stop_backend

cpp_url="http://127.0.0.1:$cpp_port"
(
    cd "$repo_dir"
    exec env \
        JWT_SECRET="$jwt_secret" \
        ADMIN_PASSWORD="$admin_password" \
        WG_ENABLED=false \
        SINGBOX_MANAGED=false \
        CONFIG_HASH_SEED=parity-config-seed \
        STATIC_DIR="$repo_dir/frontend/dist" \
        "$cpp_bin" "$database" "$repo_dir/migrations" \
        127.0.0.1 "$cpp_port"
) >"$work_dir/cpp.log" 2>&1 &
active_pid=$!
wait_ready "$cpp_url" "$work_dir/cpp.log"
cpp_token=$(login_token "$cpp_url")
curl -fsS \
    -H "Authorization: Bearer $cpp_token" \
    "$cpp_url/api/hosts/self/config" |
    jq --sort-keys . >"$work_dir/cpp-config.json"

if ! diff -u "$work_dir/rust-config.json" "$work_dir/cpp-config.json"; then
    echo "Rust/C++ rendered-config parity failed" >&2
    exit 1
fi

echo "Rust/C++ database and rendered-config parity passed"
