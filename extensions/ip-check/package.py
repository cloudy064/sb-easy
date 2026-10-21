"""Collect only licenses relevant to this standard-library frozen worker."""
import importlib.metadata
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[2]
target = root / "build/windows-release/licenses/ip-check.txt"
target.parent.mkdir(parents=True, exist_ok=True)
parts = ["sb-easy IP checker: Python standard-library runtime; no mitmproxy dependency.\n"]
parts.append("SQLite (Python sqlite3 runtime) is dedicated to the public domain.\nhttps://www.sqlite.org/copyright.html\n")
license_file = Path(sys.base_prefix) / "LICENSE.txt"
if not license_file.is_file():
    license_file = Path(sys.base_prefix) / "LICENSE"
if not license_file.is_file():
    raise SystemExit("Python license is missing")
parts.append("\n=== Python ===\n" + license_file.read_text(encoding="utf-8", errors="replace"))
distribution = importlib.metadata.distribution("pyinstaller")
for path in distribution.files or []:
    if "/licenses/" in str(path).replace("\\", "/"):
        actual = Path(distribution.locate_file(path))
        if actual.is_file():
            parts.append("\n=== PyInstaller / " + str(path) + " ===\n" + actual.read_text(encoding="utf-8", errors="replace"))
if len(parts) < 4:
    raise SystemExit("PyInstaller redistribution notice is missing")
for name in ("SOURCES.md", "Python-Third-Party.rst", "OpenSSL.txt"):
    notice = Path(__file__).resolve().parent / "licenses" / name
    parts.append("\n=== " + name + " ===\n" + notice.read_text(encoding="utf-8"))
target.write_text("\n".join(parts), encoding="utf-8")
data_notice = Path(__file__).resolve().parent / "licenses" / "ip-data.txt"
target.with_name("ip-data.txt").write_bytes(data_notice.read_bytes())
print("IP checker Python/PyInstaller/third-party runtime notices collected.")
