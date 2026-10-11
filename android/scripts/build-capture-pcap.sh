#!/usr/bin/env bash
set -euo pipefail
readonly ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly TARGET="${1:-$ROOT/.libbox-src}/experimental/sbcapture"
readonly ARCHIVE="$ROOT/third_party/libpcap-1.10.6.tar.xz"
echo 'ec97d1206bdd19cb6bdd043eaa9f0037aa732262ec68e070fd7c7b5f834d5dfc  '"$ARCHIVE" | sha256sum -c -
mkdir -p "$TARGET/pcap-source"
tar -xf "$ARCHIVE" -C "$TARGET/pcap-source" --strip-components=1
for abi in arm64-v8a armeabi-v7a x86 x86_64; do
    cmake -S "$TARGET/pcap-source" -B "$TARGET/pcap-build/$abi" \
        -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$abi" -DANDROID_PLATFORM=android-21 \
        -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DPCAP_TYPE=null -DENABLE_REMOTE=OFF -DDISABLE_DBUS=ON \
        -DDISABLE_BLUETOOTH=ON -DDISABLE_NETMAP=ON -DDISABLE_RDMA=ON
    cmake --build "$TARGET/pcap-build/$abi" --target pcap_static -j4
done
