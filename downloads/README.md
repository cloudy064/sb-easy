# Download artifacts

Place the current ARM64 Android build at `sb-easy-android.apk` and the fallback
multi-ABI build at `sb-easy-android-universal.apk`. Architecture-specific APKs
and checksum artifacts in this directory are intentionally ignored by Git and
mounted read-only into the production container by `docker-compose.yml`.
