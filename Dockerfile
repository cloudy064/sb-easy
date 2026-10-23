# syntax=docker/dockerfile:1

# Base images are parameterized so environments behind a registry mirror can
# override them.
ARG C_IMAGE=debian:bookworm-slim
ARG NODE_IMAGE=node:20-alpine
ARG DEBIAN_IMAGE=debian:bookworm-slim
ARG GO_IMAGE=golang:1.26-bookworm

FROM ${GO_IMAGE} AS singbox-bridge-builder
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
RUN apt-get -o Acquire::Retries=3 -o APT::Update::Error-Mode=any update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
        ca-certificates gcc git libc6-dev python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY config/runtime-versions.json /opt/runtime/config/runtime-versions.json
COPY scripts/runtime-manifest.py /opt/runtime/scripts/runtime-manifest.py
RUN SINGBOX_VERSION=$(python3 /opt/runtime/scripts/runtime-manifest.py get sing_box.version) \
    && SINGBOX_REVISION=$(python3 /opt/runtime/scripts/runtime-manifest.py get sing_box.source_revision) \
    && git clone --depth 1 --branch "v${SINGBOX_VERSION}" \
        https://github.com/SagerNet/sing-box.git sing-box \
    && test "$(git -C sing-box rev-parse HEAD)" = "${SINGBOX_REVISION}"
COPY singbox-bridge/ /src/sing-box/cmd/sb-easy-bridge/
WORKDIR /src/sing-box
RUN --mount=type=cache,target=/go/pkg/mod,id=sb-easy-singbox-go-mod-glibc \
    --mount=type=cache,target=/root/.cache/go-build,id=sb-easy-singbox-go-build-glibc \
    export GOTOOLCHAIN=local CGO_ENABLED=1; \
    SINGBOX_VERSION=$(python3 /opt/runtime/scripts/runtime-manifest.py get sing_box.version); \
    python3 cmd/sb-easy-bridge/prepare-overlay.py --output /tmp/sb-easy-bridge-overlay.json && \
    go build \
        -modfile /tmp/sb-easy-bridge-overlay.mod \
        -buildmode=c-archive \
        -trimpath \
        -tags 'with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,netgo,osusergo,badlinkname,tfogo_checklinkname0' \
        -ldflags "-s -w -buildid= -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=${SINGBOX_VERSION}" \
        -o /out/libsb_easy_singbox.a \
        ./cmd/sb-easy-bridge \
    && test -s /out/libsb_easy_singbox.a \
    && test -s /out/libsb_easy_singbox.h

# Explicit CI target: real SS2022 TCP/UDP, quota/revocation and cancellation.
FROM singbox-bridge-builder AS singbox-bridge-tests
RUN --network=none --mount=type=cache,target=/go/pkg/mod,id=sb-easy-singbox-go-mod-glibc \
    --mount=type=cache,target=/root/.cache/go-build,id=sb-easy-singbox-go-build-glibc \
    CGO_ENABLED=1 GOTOOLCHAIN=local go test -race -count=1 \
        -modfile /tmp/sb-easy-bridge-overlay.mod -tags with_clash_api ./cmd/sb-easy-bridge

# ===== Stage 1: Build C server and polling agent =====
FROM ${C_IMAGE} AS backend-builder
RUN apt-get -o Acquire::Retries=3 -o APT::Update::Error-Mode=any update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
    ca-certificates \
    cmake \
    gcc \
    pkg-config \
    libcurl4-openssl-dev \
    libyaml-dev \
    git \
    libsqlite3-dev \
    libssl-dev \
    make \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY c /src/c
COPY migrations /src/migrations
COPY config/client-releases.json /src/config/client-releases.json
COPY --from=singbox-bridge-builder /out /opt/sb-easy-singbox
RUN --mount=type=cache,target=/src/build,id=sb-easy-c-panel-build,sharing=locked \
    cmake -S c -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=OFF \
        -DSB_EASY_EMBED_SINGBOX=ON \
        -DSB_EASY_SINGBOX_BRIDGE_LIBRARY=/opt/sb-easy-singbox/libsb_easy_singbox.a \
        -DSB_EASY_SINGBOX_BRIDGE_INCLUDE_DIR=/opt/sb-easy-singbox \
        -DSB_EASY_WARNINGS_AS_ERRORS=ON \
    && cmake --build build \
        --target sb-easy-c-render sb-easy-c-server sb-easy-c-agent sb-easy-singbox-embedded-smoke \
        --parallel 2 \
    && build/sb-easy-singbox-embedded-smoke \
    && install -d /out \
    && install -m 0755 build/sb-easy-c-render /out/sb-easy-c-render \
    && install -m 0755 build/sb-easy-c-server /out/sb-easy-c-server \
    && install -m 0755 build/sb-easy-c-agent /out/sb-easy-c-agent

# ===== Stage 1b: Bundle sing-box binary =====
# The managed server/agent embed the engine. Retain the pinned CLI for config
# checking, diagnostics, and the independent client used by integration tests.
FROM ${DEBIAN_IMAGE} AS singbox
ARG TARGETARCH
RUN apt-get -o Acquire::Retries=3 -o APT::Update::Error-Mode=any update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY config/runtime-versions.json /opt/runtime/config/runtime-versions.json
COPY scripts/runtime-manifest.py /opt/runtime/scripts/runtime-manifest.py
RUN --mount=type=cache,target=/var/cache/sb-easy-download set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) A=amd64 ;; \
      arm64) A=arm64 ;; \
      arm) A=armv7 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    CORE_VERSION=$(python3 /opt/runtime/scripts/runtime-manifest.py get sing_box.version); \
    ARCHIVE="/var/cache/sb-easy-download/sing-box-${CORE_VERSION}-${A}.tgz"; \
    python3 /opt/runtime/scripts/runtime-manifest.py download "linux-${A}" "${ARCHIVE}"; \
    tar -xzf "${ARCHIVE}" -C /tmp; \
    install -m 0755 "/tmp/sing-box-${CORE_VERSION}-linux-${A}/sing-box" /usr/local/bin/sing-box; \
    /usr/local/bin/sing-box version

# Isolated CI target; never starts a TUN/WireGuard interface or host service.
FROM backend-builder AS backend-tests
RUN apt-get -o Acquire::Retries=3 -o APT::Update::Error-Mode=any update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY testdata /src/testdata
RUN --mount=type=cache,target=/src/build,id=sb-easy-c-panel-build,sharing=locked \
    cmake -S c -B build -DBUILD_TESTING=ON \
        -DSB_EASY_PROXY_TEST_CLIENT=/usr/local/bin/sing-box \
    && cmake --build build --parallel 2
RUN --network=none --mount=type=cache,target=/src/build,id=sb-easy-c-panel-build,sharing=locked \
    ctest --test-dir build --output-on-failure --timeout 180 --parallel 2

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
COPY config/client-releases.json config/runtime-versions.json /app/config/
RUN npm run build

# ===== Stage 2b: Build the standalone Svelte Agent UI =====
FROM ${NODE_IMAGE} AS agent-ui-builder
WORKDIR /app/agent-ui
COPY agent-ui/package.json agent-ui/package-lock.json ./
RUN npm ci
COPY agent-ui/ .
RUN npm run check && npm run build

# ===== Stage 3: Runtime =====
FROM ${DEBIAN_IMAGE}
RUN apt-get -o Acquire::Retries=3 -o APT::Update::Error-Mode=any update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
    wireguard-tools \
    iptables \
    iproute2 \
    ca-certificates \
    curl \
    libbrotli1 \
    libcurl4 \
    libyaml-0-2 \
    libsqlite3-0 \
    libssl3 \
    libzstd1 \
    procps \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=backend-builder /out/sb-easy-c-server /usr/local/bin/sb-easy
COPY --from=backend-builder /out/sb-easy-c-agent /usr/local/bin/sb-easy-agent
COPY --from=backend-builder /out/sb-easy-c-render /usr/local/bin/sb-easy-c-render
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist
COPY --from=agent-ui-builder /app/agent-ui/dist /usr/share/sb-easy/agent-ui
COPY config/runtime-versions.json config/client-releases.json /usr/share/sb-easy/
COPY migrations /app/migrations
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Managed sing-box by default: the C server/agent host the engine in process.
ENV BIND_ADDR=0.0.0.0:51821 \
    DATABASE_URL=sqlite:/app/data/sb-easy.db?mode=rwc \
    MIGRATIONS_DIR=/app/migrations \
    STATIC_DIR=/app/frontend/dist \
    AGENT_UI_PATH=/usr/share/sb-easy/agent-ui \
    SINGBOX_MANAGED=true \
    SINGBOX_BIN=/usr/local/bin/sing-box \
    SELF_SINGBOX_CONFIG_PATH=/app/data/sing-box.gen.json \
    SINGBOX_API_URL=http://127.0.0.1:9090 \
    LOG_LEVEL=info

EXPOSE 51821
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["sb-easy"]
