# Windows development preview dependencies

- **Shared sbj JSON implementation**, compiled from this repository's
  `c/src/json.c`. Its Grisu2 number formatter (`c/src/json_grisu.inc`) is a C port
  of code from nlohmann/json under the MIT license. The retained notice is
  `licenses/sbj-grisu2-MIT.txt`; upstream source and license:
  <https://github.com/nlohmann/json/tree/v3.12.0>.
- **Microsoft.Web.WebView2 SDK 1.0.4258.31**, Microsoft's WebView2 SDK license:
  <https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.4258.31>.
  The pinned NuGet package restored under the build directory contains the
  authoritative license and notices. The C host uses C COM interfaces and links
  the loader import library; `WebView2Loader.dll` ships beside `sb-easy.exe`.
- **Vue 3**, MIT license: <https://github.com/vuejs/core/blob/main/LICENSE>.
  Exact frontend dependency versions are recorded in `ui/package-lock.json`.

The WebView2 SDK archive is SHA-256 pinned in `CMakeLists.txt`. The WebView2
Evergreen Runtime is installed separately and receives its own updates. There is
no separate C++ JSON library in the Windows build.

This preview does not bundle sing-box, Wintun or an installer. The optional
`scripts/prepare-core.ps1` downloads the official **sing-box 1.13.12 Windows x64**
archive directly from its upstream release and verifies the pinned SHA-256
`e93fc531134eb1beb4efa3c74990a24e48456098a31c03b60d5ddf17f223cf98`.
It preserves that archive's `LICENSE` beside the extracted executable and
`libcronet.dll`. See the [official release](https://github.com/SagerNet/sing-box/releases/tag/v1.13.12)
and its [license](https://github.com/SagerNet/sing-box/blob/v1.13.12/LICENSE).
A distributable VPN release that bundles these components must add their notices,
corresponding-source obligations and signed artifacts before shipping them.
