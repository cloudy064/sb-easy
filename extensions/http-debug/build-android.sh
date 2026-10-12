#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
build="$root/build/httpdebug-android"
mkdir -p "$build"
wheels="$build/wheels"
if [[ ! -d "$wheels/.git" ]]; then
    git clone https://github.com/emanuele-f/chaquopy-wheels.git "$wheels"
fi
git -C "$wheels" fetch origin 1c9d6dc79065c1fbf2e9f239b99577b1219e05a8
git -C "$wheels" checkout --detach 1c9d6dc79065c1fbf2e9f239b99577b1219e05a8
export SB_ANDROID_WHEELS="$wheels"
: "${SB_PYTHON:=python3.13}"
export SB_PYTHON
bash "$root/android/gradlew" -p "$root/extensions/http-debug/android" --no-daemon assembleArm64Debug assembleX86_64Debug
cp "$root/extensions/http-debug/android/app/build/outputs/apk/arm64/debug/app-arm64-debug.apk" "$build/http-debug-1.0.0-arm64-v8a.apk"
cp "$root/extensions/http-debug/android/app/build/outputs/apk/x86_64/debug/app-x86_64-debug.apk" "$build/http-debug-1.0.0-x86_64.apk"
echo 'Plugin APKs built. Generate store pins with package.py before building the Android host.'
