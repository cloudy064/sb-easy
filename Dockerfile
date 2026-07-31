# syntax=docker/dockerfile:1

# Base images are parameterized so environments behind a registry mirror can
# override them.
ARG CXX_IMAGE=debian:bookworm-slim
ARG NODE_IMAGE=node:20-alpine
ARG DEBIAN_IMAGE=debian:bookworm-slim

# ===== Stage 1: Build C++ server and polling agent =====
FROM ${CXX_IMAGE} AS backend-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    cmake \
    g++ \
    git \
    libjsoncpp-dev \
    libsqlite3-dev \
    libssl-dev \
    make \
    uuid-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY cpp /src/cpp
COPY migrations /src/migrations
RUN --mount=type=cache,target=/src/build \
    cmake -S cpp -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=OFF \
        -DSB_EASY_WARNINGS_AS_ERRORS=ON \
    && cmake --build build \
        --target sb-easy-cpp sb-easy-cpp-server sb-easy-cpp-agent \
        --parallel 2 \
    && install -d /out \
    && install -m 0755 build/sb-easy-cpp /out/sb-easy-cpp \
    && install -m 0755 build/sb-easy-cpp-server /out/sb-easy-cpp-server \
    && install -m 0755 build/sb-easy-cpp-agent /out/sb-easy-cpp-agent

# ===== Stage 1b: Bundle sing-box binary =====
# So the image ships one artifact: sb-easy can supervise sing-box itself
# (SINGBOX_MANAGED=true) with no separate sing-box install.
FROM ${DEBIAN_IMAGE} AS singbox
ARG SINGBOX_VERSION=1.13.12
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/var/cache/sb-easy-download set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) A=amd64 ;; \
      arm64) A=arm64 ;; \
      arm) A=armv7 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --http1.1 --retry 5 --retry-all-errors --retry-delay 2 \
      --retry-max-time 600 --connect-timeout 15 --max-time 180 \
      --speed-time 30 --speed-limit 1024 --continue-at - -fsSL \
      "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${A}.tar.gz" \
      -o /var/cache/sb-easy-download/sb.tgz; \
    tar -xzf /var/cache/sb-easy-download/sb.tgz -C /tmp; \
    install -m 0755 "/tmp/sing-box-${SINGBOX_VERSION}-linux-${A}/sing-box" /usr/local/bin/sing-box; \
    /usr/local/bin/sing-box version

# ===== Stage 2: Build frontend =====
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
    libbrotli1 \
    libjsoncpp25 \
    libsqlite3-0 \
    libssl3 \
    libstdc++6 \
    libuuid1 \
    libzstd1 \
    procps \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=backend-builder /out/sb-easy-cpp-server /usr/local/bin/sb-easy
COPY --from=backend-builder /out/sb-easy-cpp-agent /usr/local/bin/sb-easy-agent
COPY --from=backend-builder /out/sb-easy-cpp /usr/local/bin/sb-easy-cpp
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist
COPY migrations /app/migrations
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Managed sing-box by default: the C++ server supervises the bundled process.
ENV BIND_ADDR=0.0.0.0:51821 \
    DATABASE_URL=sqlite:/app/data/sb-easy.db?mode=rwc \
    MIGRATIONS_DIR=/app/migrations \
    STATIC_DIR=/app/frontend/dist \
    SINGBOX_MANAGED=true \
    SINGBOX_BIN=/usr/local/bin/sing-box \
    SELF_SINGBOX_CONFIG_PATH=/app/data/sing-box.gen.json \
    SINGBOX_API_URL=http://127.0.0.1:9090 \
    LOG_LEVEL=info

EXPOSE 51821
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["sb-easy"]
