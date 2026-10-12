"""Build a legacy capture bundle; package-plugins.py now owns catalog generation.

No downloaded installer is executed. File names and order are defined in the
client, so bundles cannot contain paths, scripts, links or extra files.
"""
import argparse
import hashlib
from pathlib import Path
import struct

parser = argparse.ArgumentParser()
parser.add_argument('package', type=Path, help='Unpacked capture extension package')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
files = ['payload/extension.json', 'payload/sb-easy-capture.exe',
         'payload/capture/WinDivert.dll', 'payload/capture/WinDivert64.sys',
         'payload/licenses/WinDivert.txt', 'payload/licenses/libpcap.txt',
         'payload/licenses/vue.txt', 'payload/licenses/sbj-grisu2-MIT.txt',
         'ui/view.js', 'ui/view.css']
bundle = bytearray(b'SBECP001')
for name in files:
    data = (args.package / name).read_bytes()
    if not data or len(data) > 16 * 1024 * 1024:
        raise ValueError(name)
    bundle += struct.pack('<I', len(data)) + data
digest = hashlib.sha256(bundle).hexdigest()
name = f'capture-1.0.0-{digest[:16]}.sbe'
(root / 'build' / name).write_bytes(bundle)
print('Generate all trusted release pins with package-plugins.py before rebuilding the host.')
print(root / 'build' / name)
print(f'SHA256 {digest}; {len(bundle)} bytes')
