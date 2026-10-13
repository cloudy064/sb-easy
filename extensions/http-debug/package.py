"""Collect the Windows plugin's license notices.
Run with the same Python environment used to freeze the engine.
"""
from pathlib import Path
from importlib import metadata
import argparse

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--licenses-only', action='store_true')
args = parser.parse_args()
lines = []
for dist in sorted(metadata.distributions(), key=lambda d: d.metadata['Name'].lower()):
    lines.append(f"\n=== {dist.metadata['Name']} {dist.version} ===\n")
    lines.append(f"Home: {dist.metadata.get('Home-page', '')}\nLicense: {dist.metadata.get('License-Expression', dist.metadata.get('License', 'See below'))}\n")
    for file in dist.files or []:
        if any(word in file.name.upper() for word in ('LICENSE', 'COPYING', 'NOTICE')):
            path = dist.locate_file(file)
            if path.is_file() and path.stat().st_size < 1024 * 1024:
                lines.append(path.read_text(encoding='utf-8', errors='replace'))
destination = root/'build/windows-release/licenses/http-debug.txt'
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text('\n'.join(lines), encoding='utf-8')
