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
builds the AAR with the pinned gomobile and Android NDK versions.

Each sb-easy Android GitHub release also carries
`sing-box-1.13.12-source.tar.gz`, exported from the exact embedded revision, so
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
