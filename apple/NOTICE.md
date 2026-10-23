# Third-party components and redistribution

The native clients reuse this repository's C11 JSON/proxy parser and use sing-box
libbox at the exact version/revision in `config/runtime-versions.json`.

- sing-box: <https://github.com/SagerNet/sing-box>, GNU General Public License v3
  or later. The Apple adapter changes are in `libbox-overlay/`. The build script
  preserves the upstream source/license and emits a corresponding-source archive,
  build script and revision/overlay manifest next to the XCFramework. Binary
  redistributors must provide the complete corresponding source and required
  notices under the applicable licenses, including this application's source.
- SagerNet gomobile: <https://github.com/SagerNet/gomobile>, BSD-style license;
  version is pinned by the shared runtime manifest.
- libyaml 0.2.5: <https://github.com/yaml/libyaml>, MIT license. Its verified source
  distribution, including LICENSE, is copied under `Vendor/libyaml` by the build
  script. That generated dependency directory is not committed.
- Apple SDK frameworks are supplied by Xcode and are not redistributed in this
  repository. Use of those frameworks and distribution channels requires the
  applicable Apple agreements and provisioning.

No prebuilt or third-party-signed Apple executable is bundled here. The generated
source archive is an aid to compliant redistribution; it does not waive source,
license or signing obligations for a distributor's complete app package.
