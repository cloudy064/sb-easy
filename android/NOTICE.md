# Open-source notice

The sb-easy Android client links the sing-box `libbox` library into the APK.

- Project: sing-box
- Copyright: 2022–2026 nekohasekai and contributors
- License: GNU General Public License, version 3 or later
- Upstream source: <https://github.com/SagerNet/sing-box>
- Embedded version: 1.13.12
- Embedded revision: `1086ab2563320e0da0c23b3a491d8dfa0939dff4`

The libbox build is reproducible through [`scripts/build-libbox.sh`](scripts/build-libbox.sh).
The script fetches the exact corresponding source, verifies its revision, and
applies the GPL capture extension in `libbox-overlay/` with
`scripts/apply-capture-overlay.py`, and builds the AAR with the pinned gomobile
and Android NDK versions. The extension preserves the upstream networking stack
and adds opt-in raw TUN packet capture and connection attribution.

The capture extension statically links libpcap 1.10.6 for standard BPF capture
filter compilation and user-space packet evaluation (BSD-style licenses).
The unmodified corresponding source and license are included in
`third_party/libpcap-1.10.6.tar.xz` (`LICENSE` inside the archive).
Upstream: <https://www.tcpdump.org/> and <https://github.com/the-tcpdump-group/libpcap>.
SHA-256: `ec97d1206bdd19cb6bdd043eaa9f0037aa732262ec68e070fd7c7b5f834d5dfc`.
`scripts/build-capture-pcap.sh` verifies this archive and builds static libraries
for all four Android ABIs with the pinned NDK. Rebuilding additionally requires
CMake, flex, bison and xz/tar. Host Go tests require the libpcap development package.
Only the null capture backend is compiled; the VPN supplies the packets directly.
This product includes software developed by the Computer Systems Engineering
Group at Lawrence Berkeley Laboratory. Upstream copyright notices, including
those of The Regents of the University of California and The Tcpdump Group,
are preserved in the bundled unmodified source archive; the top-level license
is also reproduced in `third_party/libpcap-LICENSE`.

Each sb-easy Android GitHub release also carries
`sing-box-1.13.12-sb-capture-source.tar.gz`, containing the pinned upstream
source plus the capture extension and routing hooks used in the embedded build, so
APK recipients can obtain the corresponding source without relying on a moving
branch or tag.

The GPL grants recipients the right to obtain, study, modify, and redistribute
the corresponding source under its terms. The full license text is available
in the pinned upstream source as `LICENSE` and from
<https://www.gnu.org/licenses/gpl-3.0.html>.

This software is provided without warranty, including implied warranties of
merchantability or fitness for a particular purpose.

The Android client also includes ZXing and ZXing Android Embedded for local
camera and gallery QR-code decoding. They are distributed under the Apache
License 2.0:

- ZXing: <https://github.com/zxing/zxing>
- ZXing Android Embedded: <https://github.com/journeyapps/zxing-android-embedded>
