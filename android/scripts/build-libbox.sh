#!/usr/bin/env bash
set -euo pipefail

readonly LIBBOX_VERSION="1.13.12"
readonly LIBBOX_REVISION="1086ab2563320e0da0c23b3a491d8dfa0939dff4"
readonly GOMOBILE_VERSION="v0.1.12"
readonly NDK_VERSION="28.0.13004108"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ANDROID_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly SOURCE_DIR="${SB_EASY_LIBBOX_SOURCE:-$ANDROID_ROOT/.libbox-src}"
readonly OUTPUT_DIR="$ANDROID_ROOT/libbox-bridge/libs"

if [[ -z "${ANDROID_HOME:-}" ]]; then
    echo "ANDROID_HOME is required" >&2
    exit 1
fi
if [[ -z "${JAVA_HOME:-}" ]]; then
    echo "JAVA_HOME is required" >&2
    exit 1
fi

readonly NDK_DIR="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/$NDK_VERSION}"
if [[ ! -f "$NDK_DIR/source.properties" ]]; then
    echo "Android NDK $NDK_VERSION is required at $NDK_DIR" >&2
    exit 1
fi
readonly INSTALLED_NDK_VERSION="$(sed -n 's/^Pkg.Revision[[:space:]]*=[[:space:]]*//p' "$NDK_DIR/source.properties" | tr -d '\r')"
if [[ "$INSTALLED_NDK_VERSION" != "$NDK_VERSION" ]]; then
    echo "Expected Android NDK $NDK_VERSION, found $INSTALLED_NDK_VERSION" >&2
    exit 1
fi
export ANDROID_NDK_HOME="$NDK_DIR"
export ANDROID_NDK_ROOT="$NDK_DIR"

if [[ ! -d "$SOURCE_DIR/.git" ]]; then
    git clone --depth 1 --branch "v$LIBBOX_VERSION" \
        https://github.com/SagerNet/sing-box.git "$SOURCE_DIR"
else
    git -C "$SOURCE_DIR" fetch --depth 1 origin "v$LIBBOX_VERSION"
    git -C "$SOURCE_DIR" checkout --detach "v$LIBBOX_VERSION"
fi

readonly CHECKED_OUT_REVISION="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
if [[ "$CHECKED_OUT_REVISION" != "$LIBBOX_REVISION" ]]; then
    echo "Expected sing-box revision $LIBBOX_REVISION, found $CHECKED_OUT_REVISION" >&2
    exit 1
fi

go install "github.com/sagernet/gomobile/cmd/gomobile@$GOMOBILE_VERSION"
go install "github.com/sagernet/gomobile/cmd/gobind@$GOMOBILE_VERSION"
readonly GO_MOBILE_BIN="$(go env GOPATH)/bin"
export PATH="$GO_MOBILE_BIN:$PATH"
gomobile init

(
    cd "$SOURCE_DIR"
    go run ./cmd/internal/build_libbox -target android
)

mkdir -p "$OUTPUT_DIR"
install -m 0644 "$SOURCE_DIR/libbox.aar" "$OUTPUT_DIR/libbox.aar"
printf 'sing-box %s (%s), gomobile %s, NDK %s\n' \
    "$LIBBOX_VERSION" "$LIBBOX_REVISION" "$GOMOBILE_VERSION" "$NDK_VERSION"
sha256sum "$OUTPUT_DIR/libbox.aar"
