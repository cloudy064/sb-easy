#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ANDROID_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly MANIFEST_READER="$ANDROID_ROOT/../scripts/runtime-manifest.py"
readonly LIBBOX_VERSION="$(python3 "$MANIFEST_READER" get sing_box.version)"
readonly LIBBOX_REVISION="$(python3 "$MANIFEST_READER" get sing_box.source_revision)"
readonly GOMOBILE_VERSION="$(python3 "$MANIFEST_READER" get android.gomobile_version)"
readonly NDK_VERSION="$(python3 "$MANIFEST_READER" get android.ndk_version)"
readonly SOURCE_DIR="${SB_EASY_LIBBOX_SOURCE:-$ANDROID_ROOT/.libbox-src}"
readonly OUTPUT_DIR="${SB_EASY_LIBBOX_OUTPUT:-$ANDROID_ROOT/libbox-bridge/libs}"

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
    if ! git -C "$SOURCE_DIR" cat-file -e "$LIBBOX_REVISION^{commit}" 2>/dev/null; then
        git -C "$SOURCE_DIR" -c http.connectTimeout=15 -c http.lowSpeedLimit=1024 -c http.lowSpeedTime=60 \
            fetch --depth 1 origin "v$LIBBOX_VERSION"
    fi
    git -C "$SOURCE_DIR" checkout --detach "$LIBBOX_REVISION"
fi

readonly CHECKED_OUT_REVISION="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
if [[ "$CHECKED_OUT_REVISION" != "$LIBBOX_REVISION" ]]; then
    echo "Expected sing-box revision $LIBBOX_REVISION, found $CHECKED_OUT_REVISION" >&2
    exit 1
fi

python3 "$SCRIPT_DIR/apply-capture-overlay.py" "$SOURCE_DIR"
bash "$SCRIPT_DIR/build-capture-pcap.sh" "$SOURCE_DIR"

mkdir -p "$OUTPUT_DIR"
readonly BUILD_STAMP="$(mktemp "$OUTPUT_DIR/.libbox-inputs.XXXXXX")"
trap 'rm -f "$BUILD_STAMP"' EXIT
python3 "$SCRIPT_DIR/libbox-provenance.py" prepare --source "$SOURCE_DIR" --output "$BUILD_STAMP"

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
python3 "$SCRIPT_DIR/libbox-provenance.py" finish --source "$SOURCE_DIR" --stamp "$BUILD_STAMP" \
    --aar "$OUTPUT_DIR/libbox.aar" --output "$OUTPUT_DIR/libbox-provenance.json"
printf 'sing-box %s (%s), gomobile %s, NDK %s\n' \
    "$LIBBOX_VERSION" "$LIBBOX_REVISION" "$GOMOBILE_VERSION" "$NDK_VERSION"
sha256sum "$OUTPUT_DIR/libbox.aar"
