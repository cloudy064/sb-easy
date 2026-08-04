ARG BUILD_IMAGE=debian:bookworm-slim
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${BUILD_IMAGE} AS builder
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
RUN cmake -S cpp -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=ON \
        -DSB_EASY_WARNINGS_AS_ERRORS=ON \
    && cmake --build build \
        --target sb-easy-cpp sb-easy-cpp-server sb-easy-cpp-agent \
                 sb-easy-core-tests sb-easy-http-tests sb-easy-agent-tests \
        --parallel 2 \
    && ctest --test-dir build --output-on-failure

FROM ${RUNTIME_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libjsoncpp25 \
    libsqlite3-0 \
    libssl3 \
    libuuid1 \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/build/sb-easy-cpp /usr/local/bin/sb-easy-cpp
COPY --from=builder /src/build/sb-easy-cpp-server /usr/local/bin/sb-easy-cpp-server
COPY --from=builder /src/build/sb-easy-cpp-agent /usr/local/bin/sb-easy-cpp-agent
COPY --from=builder /src/migrations /usr/share/sb-easy/migrations

# Incremental parity image; the production entrypoint remains Rust for now.
ENTRYPOINT ["sb-easy-cpp"]
CMD ["--version"]
