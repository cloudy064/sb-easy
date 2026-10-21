"""Build the optional IP check's offline, read-only SQLite data snapshot.

This is an explicit maintainer command, never run during a user's IP check.
Download URLs, dates and expected digests live in data-sources.json. Updating
that reviewed lock file is how a new upstream snapshot is selected. Downloads
are bounded and cached; a failed download/validation cannot replace the old DB.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import shutil
import tempfile
import time
import urllib.request
import urllib.parse
from contextlib import contextmanager

MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_DECODED = 256 * 1024 * 1024
MAX_DATABASE = 110 * 1024 * 1024
MAX_ROWS = 3_000_000
SOURCE_IDS = {"dbip-country", "dbip-asn", "x4b-datacenter", "x4b-vpn", "tor-exit"}
SNAPSHOT_DIR = Path(__file__).resolve().parent / "snapshots"
SCHEMA = """
CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE sources(id TEXT PRIMARY KEY,name TEXT NOT NULL,url TEXT NOT NULL,
 license TEXT NOT NULL,updated_at TEXT NOT NULL,retrieved_at TEXT NOT NULL,
 status TEXT NOT NULL,families TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE ranges(source_id TEXT NOT NULL,family INTEGER NOT NULL,
 start BLOB NOT NULL,end BLOB NOT NULL,country_code TEXT,asn INTEGER,
 organization TEXT,network TEXT,PRIMARY KEY(source_id,family,start)) WITHOUT ROWID;
"""


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def digest_file(path, algorithm="sha256"):
    h = hashlib.new(algorithm)
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("snapshot redirects are not permitted; pin the final HTTPS URL")


def download(url, path, expected_sha256, *, opener=None, max_bytes=MAX_DOWNLOAD):
    """Download one pinned HTTPS snapshot, validating before atomic replacement."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("snapshot URL must be HTTPS without credentials")
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise ValueError("snapshot SHA-256 is required")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    opener = opener or urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "sb-easy-ip-data-builder/1", "Accept-Encoding": "identity"})
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".part", dir=path.parent)
    started = time.monotonic()
    try:
        with os.fdopen(fd, "wb") as target, opener.open(request, timeout=20) as response:
            if response.status != 200:
                raise ValueError("snapshot download did not return HTTP 200")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > max_bytes):
                raise ValueError("snapshot download exceeds size limit")
            received = 0
            while chunk := response.read(min(1024 * 1024, max_bytes + 1 - received)):
                received += len(chunk)
                if received > max_bytes or time.monotonic() - started > 180:
                    raise ValueError("snapshot download exceeds size/time limit")
                target.write(chunk)
            if not received:
                raise ValueError("empty snapshot download")
        if digest_file(temporary) != expected_sha256:
            raise ValueError("snapshot SHA-256 mismatch")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def decoded_input(path, item):
    """Bound expansion and validate any publisher digest before CSV parsing."""
    path = Path(path)
    open_input = gzip.open if item.get("compression") == "gzip" else open
    with open_input(path, "rb") as stream:
        data = stream.read(MAX_DECODED + 1)
        if len(data) > MAX_DECODED:
            raise ValueError("decompressed source exceeds size limit")
    if not data:
        raise ValueError("empty source")
    if item.get("decoded_sha1") and hashlib.sha1(data).hexdigest() != item["decoded_sha1"]:
        raise ValueError("publisher SHA-1 mismatch on uncompressed source")
    if item.get("decoded_sha256") and hashlib.sha256(data).hexdigest() != item["decoded_sha256"]:
        raise ValueError("decoded SHA-256 mismatch")
    with io.TextIOWrapper(io.BytesIO(data), encoding="utf-8-sig", newline="") as text:
        yield text


def csv_rows(stream, kind):
    """Reject ambiguous/reversed ranges and malformed metadata, never guess."""
    count = 0
    for line in csv.reader(stream):
        if not line:
            continue
        count += 1
        if count > MAX_ROWS or len(line) != (3 if kind == "country" else 4):
            raise ValueError("invalid CSV record count or field count")
        start, end = map(ipaddress.ip_address, line[:2])
        if start.version != end.version or start > end:
            raise ValueError("invalid IP range")
        country = asn = organization = None
        if kind == "country":
            country = line[2].upper()
            if not re.fullmatch(r"[A-Z]{2}", country):
                raise ValueError("invalid country code")
        else:
            if not re.fullmatch(r"[0-9]{1,10}", line[2]) or not 0 <= int(line[2]) <= 4294967295:
                raise ValueError("invalid ASN")
            asn = int(line[2])
            organization = line[3]
            if not organization or len(organization) > 512 or any(ord(ch) < 32 for ch in organization):
                raise ValueError("invalid ASN organization")
        yield start.version, start.packed, end.packed, country, asn, organization, None


def cidr_rows(stream):
    """Merge overlapping/adjacent list ranges for an unambiguous <= lookup."""
    families = {4: [], 6: []}
    count = 0
    for line in stream:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        count += 1
        if count > MAX_ROWS:
            raise ValueError("list exceeds record limit")
        network = ipaddress.ip_network(line, strict=True)
        families[network.version].append((int(network.network_address), int(network.broadcast_address)))
    for family, ranges in families.items():
        if not ranges:
            continue
        ranges.sort()
        start, end = ranges[0]
        merged = []
        for a, b in ranges[1:]:
            if a <= end + 1:
                end = max(end, b)
            else:
                merged.append((start, end))
                start, end = a, b
        merged.append((start, end))
        address = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address
        for start, end in merged:
            first, last = address(start), address(end)
            yield family, first.packed, last.packed, None, None, None, f"{first} - {last}"


def tordnsel_rows(stream):
    """Read the Tor Project's observed exits, not relay or guard addresses."""
    addresses = set()
    seen_header = False
    record_count = 0
    for line in stream:
        line = line.strip()
        if not line:
            continue
        if not seen_header:
            if line != "@type tordnsel 1.0":
                raise ValueError("unsupported Tor exit-list format")
            seen_header = True
            continue
        fields = line.split()
        if fields[0] == "ExitAddress":
            if len(fields) != 4:
                raise ValueError("invalid Tor exit address observation")
            address = ipaddress.ip_address(fields[1])
            if not address.is_global:
                raise ValueError("Tor exit observation is not a public IP")
            dt.datetime.strptime(fields[2] + " " + fields[3], "%Y-%m-%d %H:%M:%S")
            record_count += 1
            if record_count > MAX_ROWS:
                raise ValueError("Tor source exceeds record limit")
            addresses.add(f"{address}/{32 if address.version == 4 else 128}")
        elif fields[0] == "ExitNode":
            if len(fields) != 2 or not re.fullmatch(r"[A-Fa-f0-9]{40}", fields[1]):
                raise ValueError("invalid Tor exit identity")
        elif fields[0] in ("Published", "LastStatus"):
            if len(fields) != 3:
                raise ValueError("invalid Tor observation date")
            dt.datetime.strptime(fields[1] + " " + fields[2], "%Y-%m-%d %H:%M:%S")
        else:
            raise ValueError("unsupported Tor exit-list record")
    if not seen_header or not addresses:
        raise ValueError("empty Tor exit-list")
    yield from cidr_rows(addresses)


def verify_ranges(connection, source_id):
    """Check full sorted range ordering; overlapping metadata is a hard error."""
    previous_family, previous_end = None, None
    count = 0
    families = set()
    for family, start, end in connection.execute(
        "SELECT family,start,end FROM ranges WHERE source_id=? ORDER BY family,start", (source_id,)
    ):
        count += 1
        if family not in (4, 6) or len(start) != (4 if family == 4 else 16) or len(end) != len(start) or start > end:
            raise ValueError("invalid packed IP range")
        if family == previous_family and start <= previous_end:
            raise ValueError(f"overlapping source ranges: {source_id}")
        previous_family, previous_end = family, end
        families.add(family)
    if not count:
        raise ValueError(f"empty source: {source_id}")
    return count, ",".join(map(str, sorted(families)))


def validate_lock(lock):
    if lock.get("version") != 1 or not isinstance(lock.get("sources"), list):
        raise ValueError("unsupported data source lock")
    ids = [source.get("id") for source in lock["sources"]]
    if len(ids) != len(set(ids)) or set(ids) != SOURCE_IDS:
        raise ValueError("source lock must describe all five known sources exactly once")
    for source in lock["sources"]:
        if source.get("status") not in ("ready", "missing"):
            raise ValueError("invalid source status")
        if source["status"] == "missing":
            if source.get("inputs"):
                raise ValueError("missing source has inputs")
            continue
        if not source.get("inputs") or source.get("format") not in ("country", "asn", "cidr", "tordnsel"):
            raise ValueError("ready source requires supported inputs")
        for item in source["inputs"]:
            name = item.get("file", "")
            if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,180}", name) or name in (".", ".."):
                raise ValueError("invalid snapshot filename")
            if not re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", "")):
                raise ValueError("snapshot digest required")
            if "bundled" in item and not isinstance(item["bundled"], bool):
                raise ValueError("invalid bundled snapshot flag")


def acquire(lock, cache_dir, offline=False):
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    retrievals = {}
    for source in lock["sources"]:
        for item in source.get("inputs", []):
            path = cache_dir / item["file"]
            if not path.is_file() or path.stat().st_size > MAX_DOWNLOAD or digest_file(path) != item["sha256"]:
                if item.get("bundled"):
                    # Only the fixed source tree directory is supported; the
                    # reviewed lock cannot turn this into an arbitrary copy.
                    bundled = SNAPSHOT_DIR / item["file"]
                    if not bundled.is_file() or bundled.stat().st_size > MAX_DOWNLOAD or digest_file(bundled) != item["sha256"]:
                        raise ValueError("bundled snapshot is missing or invalid")
                    shutil.copyfile(bundled, path)
                elif offline:
                    raise ValueError(f"missing or invalid cached snapshot: {item['file']}")
                else:
                    download(item["url"], path, item["sha256"])
            retrievals[item["file"]] = item.get("retrieved_at") or dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return retrievals


def build_database(lock, cache_dir, output, *, offline=False):
    validate_lock(lock)
    retrievals = acquire(lock, cache_dir, offline)
    output, cache_dir = Path(output), Path(cache_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    generated_at = utc_now()
    fd, temporary = tempfile.mkstemp(prefix=output.name + ".", suffix=".building", dir=output.parent)
    os.close(fd)
    manifest_temporary = None
    connection = None
    try:
        connection = sqlite3.connect(temporary)
        connection.executescript(SCHEMA)
        connection.execute("PRAGMA user_version=1")
        connection.executemany("INSERT INTO metadata VALUES (?,?)", [("version", "1"), ("generated_at", generated_at)])
        reports = []
        for source in lock["sources"]:
            count, families = 0, ""
            if source["status"] == "ready":
                for item in source["inputs"]:
                    with decoded_input(cache_dir / item["file"], item) as stream:
                        if source["format"] == "cidr":
                            rows = cidr_rows(stream)
                        elif source["format"] == "tordnsel":
                            rows = tordnsel_rows(stream)
                        else:
                            rows = csv_rows(stream, source["format"])
                        connection.executemany("INSERT INTO ranges VALUES (?,?,?,?,?,?,?,?)", ((source["id"], *row) for row in rows))
                count, families = verify_ranges(connection, source["id"])
                if source.get("expected_min_rows") and count < source["expected_min_rows"]:
                    raise ValueError(f"snapshot is unexpectedly small: {source['id']}")
            retrieved_at = max((retrievals[item["file"]] for item in source.get("inputs", [])), default="")
            row = {key: source.get(key, "") for key in ("id", "name", "url", "license", "updated_at", "status")}
            row.update(retrieved_at=retrieved_at, families=families)
            connection.execute("INSERT INTO sources VALUES (:id,:name,:url,:license,:updated_at,:retrieved_at,:status,:families)", row)
            reports.append({**row, "record_count": count, "inputs": source.get("inputs", [])})
        connection.commit()
        connection.execute("VACUUM")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("SQLite integrity check failed")
        connection.close()
        connection = None
        size = os.path.getsize(temporary)
        if size > MAX_DATABASE:
            raise ValueError("dataset exceeds 110 MiB package budget")
        manifest = {"version": 1, "generated_at": generated_at, "file": output.name,
                    "sha256": digest_file(temporary), "size_bytes": size, "sources": reports}
        manifest_path = output.with_name("manifest.json")
        fd, manifest_temporary = tempfile.mkstemp(prefix="manifest.", suffix=".building", dir=output.parent)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        # Runtime verifies the DB/manifest pair. Interruption between replacements
        # produces an explicit unknown result, never silently stale/mixed data.
        os.replace(temporary, output)
        os.replace(manifest_temporary, manifest_path)
        return manifest
    finally:
        if connection is not None:
            connection.close()
        for path in (temporary, manifest_temporary):
            if path and os.path.exists(path):
                os.unlink(path)


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", type=Path, default=Path(__file__).with_name("data-sources.json"))
    parser.add_argument("--cache-dir", type=Path, default=root / "build/ipcheck-data")
    parser.add_argument("--output", type=Path, default=root / "build/windows-release/extensions/ip-check/data/ip-intelligence.sqlite")
    parser.add_argument("--offline", action="store_true", help="use already verified cached snapshots only")
    args = parser.parse_args()
    lock = json.loads(args.source_lock.read_text(encoding="utf-8"))
    manifest = build_database(lock, args.cache_dir, args.output, offline=args.offline)
    print(json.dumps({"file": str(args.output), "sha256": manifest["sha256"], "size_bytes": manifest["size_bytes"],
                      "sources": [{"id": s["id"], "status": s["status"], "record_count": s["record_count"]} for s in manifest["sources"]]}, indent=2))


if __name__ == "__main__":
    main()
