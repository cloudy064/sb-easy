# Base images are parameterized so environments behind a registry mirror can
# override them, e.g. --build-arg RUST_IMAGE=docker.1ms.run/library/rust:1.96-slim-bookworm
ARG RUST_IMAGE=rust:1.96-slim-bookworm
ARG NODE_IMAGE=node:20-alpine
ARG DEBIAN_IMAGE=debian:bookworm-slim

# ===== Stage 1: Build Rust Backend =====
FROM ${RUST_IMAGE} AS backend-builder
# Resilient crate fetches over a flaky proxy: retry transient failures and use
# HTTP/1.1 (proxied connections handle multiplexing poorly).
ENV CARGO_NET_RETRY=10 CARGO_HTTP_MULTIPLEXING=false
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY backend/Cargo.toml backend/
COPY agent/Cargo.toml agent/
RUN mkdir -p backend/src agent/src && \
    echo 'fn main() {}' > backend/src/main.rs && \
    echo 'fn main() {}' > agent/src/main.rs
RUN cargo build --release -p sb-easy 2>/dev/null || true

COPY backend/src backend/src/
COPY migrations migrations/
# Bust cargo's mtime-based fingerprint: COPY may set source mtimes older than the
# dummy build, making cargo skip the real rebuild and ship the stub binary.
RUN find backend/src -name '*.rs' -exec touch {} + && \
    cargo build --release -p sb-easy && \
    cp target/release/sb-easy /sb-easy && \
    test "$(stat -c%s /sb-easy)" -gt 1000000   # sanity: real binary, not the stub

# ===== Stage 1b: Bundle sing-box binary =====
# So the image ships one artifact: sb-easy can supervise sing-box itself
# (SINGBOX_MANAGED=true) with no separate sing-box install.
FROM ${DEBIAN_IMAGE} AS singbox
ARG SINGBOX_VERSION=1.13.12
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) A=amd64 ;; \
      arm64) A=arm64 ;; \
      arm) A=armv7 ;; \
      *) A=amd64 ;; \
    esac; \
    curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${A}.tar.gz" -o /tmp/sb.tgz; \
    tar -xzf /tmp/sb.tgz -C /tmp; \
    install -m 0755 "/tmp/sing-box-${SINGBOX_VERSION}-linux-${A}/sing-box" /usr/local/bin/sing-box; \
    /usr/local/bin/sing-box version

# ===== Stage 2: Build Frontend =====
FROM ${NODE_IMAGE} AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* frontend/pnpm-lock.yaml* ./
RUN if [ -f pnpm-lock.yaml ]; then \
        corepack enable && pnpm install --frozen-lockfile; \
    elif [ -f package-lock.json ]; then \
        npm ci; \
    else \
        npm install; \
    fi
COPY frontend/ .
RUN npm run build

# ===== Stage 3: Runtime =====
FROM ${DEBIAN_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools \
    iptables \
    iproute2 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=backend-builder /sb-easy /usr/local/bin/sb-easy
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist
COPY migrations /app/migrations
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Managed sing-box by default: the image supervises the bundled sing-box in
# process — no separate sing-box install needed. Override any of these at run.
ENV BIND_ADDR=0.0.0.0:51821 \
    DATABASE_URL=sqlite:/app/data/sb-easy.db?mode=rwc \
    SINGBOX_MANAGED=true \
    SINGBOX_BIN=/usr/local/bin/sing-box \
    SELF_SINGBOX_CONFIG_PATH=/app/data/sing-box.gen.json \
    SINGBOX_API_URL=http://127.0.0.1:9090 \
    RUST_LOG=info

EXPOSE 51821
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["sb-easy"]
