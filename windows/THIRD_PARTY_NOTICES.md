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

The optional `scripts/prepare-core.ps1` downloads the official **sing-box 1.13.12 Windows x64**
archive directly from its upstream release and verifies the pinned SHA-256
`e93fc531134eb1beb4efa3c74990a24e48456098a31c03b60d5ddf17f223cf98`.
It preserves that archive's `LICENSE` beside the extracted executable and
`libcronet.dll`. See the [official release](https://github.com/SagerNet/sing-box/releases/tag/v1.13.12)
and its [license](https://github.com/SagerNet/sing-box/blob/v1.13.12/LICENSE).
Packages built with `package.ps1 -IncludeCore` contain these unmodified upstream
binaries and `core/LICENSE`. Wintun is embedded by upstream sing-tun v0.8.9;
its sources and notices are at <https://github.com/SagerNet/sing-tun/tree/v0.8.9>.
Corresponding upstream source and build instructions:
<https://github.com/SagerNet/sing-box/tree/v1.13.12> (including its pinned `go.mod`
dependencies), <https://sing-box.sagernet.org/installation/build-from-source/>.
When publishing bundled binaries, provide their corresponding source in accordance
with `core/LICENSE`. Local preview packages are unsigned.

MSI packages are authored using WiX Toolset 5.0.2 with its UI extension. WiX is a
build-time tool, not a C++ implementation of the sb-easy service or desktop. End
users do not need WiX, .NET SDK or Visual Studio installed.


## tldts / tldts-core (7.0.25)

MIT-licensed public suffix parsing by Remusao and contributors, used for domain
traffic grouping including private suffixes. Distributed license texts are
`licenses/tldts.txt` and `licenses/tldts-core.txt`.

## WinDivert 2.2.2 and libpcap 1.10.6

Optional TUN capture dynamically loads the unmodified official x64 WinDivert DLL
and signed driver in sniff-only mode. WinDivert is used under LGPLv3; its full
license is distributed as `licenses/WinDivert.txt`. Users may replace the
compatible library/driver. Upstream source and build instructions:
https://github.com/basil00/WinDivert/tree/v2.2.2 and https://reqrypt.org/windivert-doc.html.

libpcap's BPF compiler/interpreter is statically built from the repository's
`android/third_party/libpcap-1.10.6.tar.xz`, using the null capture backend. No
Npcap runtime is required. Its BSD license is included as `licenses/libpcap.txt`.
Source: https://www.tcpdump.org/release/libpcap-1.10.6.tar.xz.
The pinned win_flex_bison tools are build dependencies, not shipped runtimes.
