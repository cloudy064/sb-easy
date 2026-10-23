# Build the native desktop against Debian 12, the supported runtime baseline.
ARG GO_VERSION=1.25.5
FROM golang:${GO_VERSION}-bookworm AS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build pkg-config build-essential git ca-certificates python3 ripgrep \
    libgtk-3-dev libsecret-1-dev libpolkit-gobject-1-dev libcurl4-openssl-dev \
    libssl-dev libsqlite3-dev libyaml-dev dpkg-dev gnupg openssl \
    dbus-x11 xvfb xauth gnome-keyring fonts-noto-cjk iproute2 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 1000 builder
RUN apt-get update && apt-get install -y --no-install-recommends gsettings-desktop-schemas file \
    && rm -rf /var/lib/apt/lists/*

FROM dependencies AS build
WORKDIR /src
COPY --chown=builder:builder linux linux
COPY --chown=builder:builder apple/Core apple/Core
COPY --chown=builder:builder c c
COPY --chown=builder:builder singbox-bridge singbox-bridge
COPY --chown=builder:builder config config
COPY --chown=builder:builder scripts/runtime-manifest.py scripts/runtime-manifest.py
COPY --chown=builder:builder assets/branding assets/branding
RUN chown builder:builder /src
USER builder
ENV GOTOOLCHAIN=local
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
RUN linux/scripts/build.sh /src/build/linux-desktop /src/build/linux-core
RUN --network=none ctest --test-dir build/linux-desktop -R '^linux_' --output-on-failure
RUN cd build/linux-desktop && cpack -G DEB

FROM scratch AS package
COPY --from=build /src/build/linux-desktop/*.deb /
COPY --from=build /src/build/linux-core/provenance.json /core-provenance.json
COPY --from=build /src/build/linux-desktop/ui-smoke.png /ui-smoke.png
