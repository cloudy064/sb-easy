# Linux desktop third-party notices

The native GTK application and its privileged tunnel service link the repository's
C11 agent/client/configuration code and the pinned sing-box bridge. The source
version and archive hashes are installed as `core-provenance.json`.

- sing-box: GPL-3.0-or-later, SagerNet; exact source commit and upstream source URL
  are recorded in `config/runtime-versions.json`. The bridge and dependency overlay
  sources are in `singbox-bridge/`.
- GTK 3, GLib/GIO and libsecret: LGPL-2.1-or-later, dynamically linked through system
  packages. Polkit: LGPL-2.0-or-later, dynamically linked.
- OpenSSL: Apache-2.0; libcurl: curl license; SQLite: public domain; libyaml: MIT.
- CivetWeb 1.16: MIT; QR-Code-generator 1.8.0: MIT; Argon2 20190702: Apache-2.0 /
  CC0-1.0; QuickJS-NG 0.15.1: MIT. These versions are pinned by `c/CMakeLists.txt`.
- Go standard library: BSD-3-Clause. The Go module graph comes from the pinned
  upstream sing-box source and the reviewed `singbox-bridge/prepare-overlay.py`.

A binary distributor must include the applicable license texts and provide the
complete corresponding source, build scripts and local modifications required by
the applicable licenses. A local development DEB or test repository is not a
published product release. Repository signing keys and signing credentials are
external release inputs and are not included in the source or package.
