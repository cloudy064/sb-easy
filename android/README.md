# sb-easy Android

This directory contains the managed sb-easy Android client. It embeds sing-box
1.13.12 through `libbox.aar`; no root access, external executable, local HTTP
server, or administrator account is required on the phone.

## Features

- one-time QR/deep-link enrollment with a per-device Agent token, using either
  the camera or a QR image selected from the system photo picker;
- Android Keystore AES-GCM credential storage;
- ETag configuration sync over an explicit non-VPN underlying network;
- candidate/active/rollback atomic configuration snapshots and libbox validation;
- Android `VpnService`, foreground notification, Always-on recovery, and a
  Quick Settings tile;
- live libbox traffic, connections, proxy groups, node selection, URLTest, and logs;
- a real HTTP/HTTPS route test correlated with libbox connection events;
- readable config/routing views plus a redacted JSON view;
- visible Profile/QuickJS source, config version, and sync state;
- Agent status, commands, telemetry, and latency reporting.

The server executes QuickJS. The phone only receives the generated, validated
sing-box configuration and never receives administrator credentials or script
execution privileges.

## Build

Requirements:

- JDK 17
- Android SDK platform/build-tools 36
- Android NDK 28.0.13004108
- Go supported by sing-box 1.13.12

```sh
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
export ANDROID_HOME=/path/to/android-sdk

./scripts/build-libbox.sh
./gradlew testDebugUnitTest lintDebug assembleDebug
```

The generated AAR and APK are intentionally ignored by Git. The libbox build
is pinned to sing-box revision
`1086ab2563320e0da0c23b3a491d8dfa0939dff4`, gomobile 0.1.12, and NDK
28.0.13004108.

`assembleDebug` produces architecture-specific APKs for `arm64-v8a`,
`armeabi-v7a`, `x86`, and `x86_64`, plus a larger universal APK. Most current
physical phones should use the ARM64 build; use the universal build when the
device architecture is unknown. Published builds keep these files separate so
users do not need to download native libraries for unrelated architectures.

## Enrollment

1. Install the APK matching the phone architecture from
   `app/build/outputs/apk/debug/`, normally `app-arm64-v8a-debug.apk`, or use
   `app-universal-debug.apk` as the compatibility fallback.
2. In the sb-easy Web panel, open **Devices → Add Android**.
3. Name the phone and create the ten-minute, single-use enrollment QR code.
4. Open the App, scan the code with the camera or select its screenshot from the
   system photo picker, then accept Android's VPN consent dialog.
5. Use the four tabs for connection status, proxies, route/config/log tools, and
   device settings.

The current test deployment is plain HTTP and the App calls this out visibly.
Production deployments should put the control plane behind HTTPS; the App never
offers a switch that disables TLS certificate verification.

## Verification

The checked-in project is covered by Kotlin config-inspection tests, Android
lint, APK signing/ABI inspection, C++ enrollment/rendering/HTTP contract tests,
and an end-to-end preflight that feeds a rendered Android profile to sing-box
1.13.12 `check`. A physical Android device remains necessary for the final VPN,
network-switch, Doze, and vendor-ROM acceptance pass.

## Licensing

The embedded sing-box/libbox core is GPL-3.0-or-later. See
[`NOTICE.md`](NOTICE.md) and the corresponding source/build instructions before
redistributing the APK outside controlled testing. GitHub releases include the
exact `sing-box-1.13.12-source.tar.gz` corresponding-source archive alongside
the APKs.
