ARG BUILD_IMAGE=debian:bookworm-slim
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${BUILD_IMAGE} AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    cmake \
    g++ \
    git \
    libsqlite3-dev \
    libssl-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY cpp /src/cpp
COPY migrations /src/migrations
RUN cmake -S cpp -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=ON \
    && cmake --build build \
        --target sb-easy-cpp sb-easy-core-tests \
        --parallel 2 \
    && ctest --test-dir build --output-on-failure

FROM ${RUNTIME_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libsqlite3-0 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/build/sb-easy-cpp /usr/local/bin/sb-easy-cpp
COPY --from=builder /src/migrations /usr/share/sb-easy/migrations

# This is the core/database parity image, not yet the production HTTP server.
ENTRYPOINT ["sb-easy-cpp"]
CMD ["--version"]
