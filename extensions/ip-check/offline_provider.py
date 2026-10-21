"""Read-only range intelligence, with no network capability or API fallback.

Only a bundled database is queried. Missing, unsupported and stale lists never
become a negative finding, and a negative finding never means residential/safe.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import sqlite3
import sys

from provider import public_ip

PROVIDER = "sb-easy-offline"
DATABASE_NAME = "ip-intelligence.sqlite"
MAX_DATABASE_BYTES = 110 * 1024 * 1024
# Attribution defaults are also shown when the corresponding file/row is absent.
SOURCES = {
    "dbip-country": ("DB-IP Country Lite", "https://db-ip.com/db/download/ip-to-country-lite", "CC BY 4.0", 60),
    "dbip-asn": ("DB-IP ASN Lite", "https://db-ip.com/db/download/ip-to-asn-lite", "CC BY 4.0", 60),
    "x4b-datacenter": ("X4BNet datacenter list", "https://github.com/X4BNet/lists_vpn", "MIT", 7),
    "x4b-vpn": ("X4BNet VPN list", "https://github.com/X4BNet/lists_vpn", "MIT", 7),
    "tor-exit": ("Tor exit list", "https://check.torproject.org/torbulkexitlist", "CC0-1.0", 2),
}
CHECKS = {"datacenter": "x4b-datacenter", "vpn": "x4b-vpn", "tor": "tor-exit"}


def default_data_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "data"
    return Path(__file__).resolve().parents[2] / "build/windows-release/extensions/ip-check/data"


def _text(value, limit=160):
    if (not isinstance(value, str) or not value.strip() or len(value) > limit
            or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        return None
    return value


def _date(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (AttributeError, ValueError, TypeError):
        return None


class OfflineProvider:
    """One read-only connection per batch; caller owns close/context lifetime."""

    def __init__(self, data_dir: Path | str | None = None, now: datetime | None = None):
        self.now = now or datetime.now(timezone.utc)
        if self.now.tzinfo is None:
            self.now = self.now.replace(tzinfo=timezone.utc)
        self.connection = None
        self.error = "database_missing"
        self.database = None
        self.sources = []
        path = Path(data_dir) if data_dir is not None else default_data_dir()
        file = path / DATABASE_NAME
        try:
            if not file.is_file():
                self._unavailable_sources("missing")
                return
            if not 0 < file.stat().st_size <= MAX_DATABASE_BYTES:
                raise ValueError("database_size_invalid")
            self._verify_manifest(path, file)
            # Read only cannot create/mutate files. Disable trusted schema and
            # bound query VM work even for a damaged database in the bundle.
            self.connection = sqlite3.connect(file.resolve().as_uri() + "?mode=ro", uri=True, timeout=1)
            self.connection.execute("PRAGMA query_only=ON")
            self.connection.execute("PRAGMA trusted_schema=OFF")
            self.connection.set_progress_handler(lambda: 1, 500000)
            metadata = dict(self.connection.execute("SELECT key,value FROM metadata LIMIT 32"))
            version = _text(metadata.get("version"), 64)
            generated = _text(metadata.get("generated_at"), 40)
            if version != "1" or _date(generated) is None:
                raise ValueError("invalid_database_metadata")
            self.database = {"version": version, "generated_at": generated}
            self.connection.execute("SELECT source_id,family,start,end,country_code,asn,organization,network FROM ranges LIMIT 0")
            rows = list(self.connection.execute("SELECT id,name,url,license,updated_at,retrieved_at,status,families FROM sources LIMIT 32"))
            rows = {row[0]: row for row in rows}
            for identifier, defaults in SOURCES.items():
                source = self._default_source(identifier, "missing")
                row = rows.get(identifier)
                if row:
                    _, name, url, license_name, updated, retrieved, status, families = row
                    source.update(name=_text(name, 80) or defaults[0], url=_text(url, 256) or defaults[1],
                                  license=_text(license_name, 80) or defaults[2],
                                  updated_at=_text(updated, 40), retrieved_at=_text(retrieved, 40))
                    if not source["url"].startswith("https://"):
                        source["url"] = defaults[1]
                    family_values = str(families).split(",") if families else []
                    source["families"] = [int(f) for f in family_values if f in ("4", "6")]
                    source["status"] = status if status in ("ready", "missing", "stale", "invalid") else "invalid"
                    if len(source["families"]) != len(set(family_values)) or any(f not in ("4", "6") for f in family_values):
                        source["status"] = "invalid"
                        source["families"] = []
                    if source["status"] == "ready":
                        date = _date(source["updated_at"] or source["retrieved_at"])
                        if date is None or not source["families"] or date > self.now + timedelta(days=1):
                            source["status"] = "invalid"
                        elif self.now - date > timedelta(days=defaults[3]):
                            source["status"] = "stale"
                self.sources.append(source)
            self.error = None
        except (OSError, sqlite3.Error, ValueError, TypeError):
            self.close()
            self.error = "database_invalid"
            self.database = None
            self._unavailable_sources("invalid")

    @staticmethod
    def _verify_manifest(path, file):
        manifest = path / "manifest.json"
        if not manifest.exists():
            return  # Explicit development fixtures can omit a manifest.
        if manifest.stat().st_size > 64 * 1024:
            raise ValueError("manifest_too_large")
        value = json.loads(manifest.read_text(encoding="utf-8"))
        database = value
        if (not isinstance(database, dict) or database.get("version") != 1 or database.get("file") != DATABASE_NAME
                or type(database.get("size_bytes")) is not int or database["size_bytes"] != file.stat().st_size):
            raise ValueError("database_manifest_invalid")
        digest = hashlib.sha256()
        with file.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != database.get("sha256"):
            raise ValueError("database_digest_invalid")

    def _default_source(self, identifier, status):
        name, url, license_name, _ = SOURCES[identifier]
        return {"id": identifier, "name": name, "url": url, "license": license_name,
                "updated_at": None, "retrieved_at": None, "status": status, "families": []}

    def _unavailable_sources(self, status):
        self.sources = [self._default_source(identifier, status) for identifier in SOURCES]

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _match(self, identifier, address):
        if self.connection is None:
            raise sqlite3.DatabaseError("database_closed")
        row = self.connection.execute(
            "SELECT start,end,country_code,asn,organization,network FROM ranges "
            "WHERE source_id=? AND family=? AND start<=? ORDER BY start DESC LIMIT 1",
            (identifier, address.version, address.packed)).fetchone()
        if row is None:
            return None
        start, end, country, asn, organization, network = row
        if not isinstance(start, bytes) or not isinstance(end, bytes) or len(start) != len(address.packed) or len(end) != len(start) or start > end:
            raise sqlite3.DatabaseError("invalid_range")
        if address.packed > end:
            return None
        if country is not None and (not isinstance(country, str) or len(country) != 2 or not country.isascii() or not country.isalpha()):
            raise sqlite3.DatabaseError("invalid_country")
        if asn is not None and (type(asn) is not int or not 0 < asn <= 4294967295):
            raise sqlite3.DatabaseError("invalid_asn")
        return {"country_code": country.upper() if country else None,
                "asn": f"AS{asn}" if asn else None, "organization": _text(organization),
                "network": _text(network, 64)}

    def lookup(self, ip):
        address = ipaddress.ip_address(public_ip(ip))
        sources = [dict(source, families=list(source["families"])) for source in self.sources]
        result = {"provider": PROVIDER, "queried_ip": str(address), "status": "unknown",
                  "reason": self.error, "checked_at": self.now.isoformat(), "partial": True,
                  "fields": {"country_code": None, "asn": None, "organization": None,
                             "privacy": {"is_datacenter": None, "is_vpn": None, "is_tor": None}},
                  "field_sources": {}, "checks": [], "sources": sources}
        if self.database:
            result["database"] = dict(self.database)
        matches, usable, incomplete = {}, 0, False
        for source in sources:
            identifier, status = source["id"], source["status"]
            family_supported = address.version in source["families"]
            row = None
            if status in ("ready", "stale") and family_supported:
                try:
                    row = self._match(identifier, address)
                    usable += 1
                except sqlite3.Error:
                    source["status"] = status = "invalid"
            matches[identifier] = row
            incomplete |= status != "ready" or not family_supported
            if identifier in CHECKS.values():
                check_id = next(key for key, value in CHECKS.items() if value == identifier)
                check_status = ("unavailable" if status in ("missing", "invalid") else
                                "unsupported" if not family_supported else "stale" if status == "stale" else
                                "listed" if row else "not_listed")
                check = {"id": check_id, "status": check_status, "source": identifier,
                         "updated_at": source["updated_at"]}
                if row and row["network"]:
                    check["network"] = row["network"]
                result["checks"].append(check)
                if row:
                    result["fields"]["privacy"]["is_" + check_id] = True
        for field, identifier in (("country_code", "dbip-country"), ("asn", "dbip-asn"), ("organization", "dbip-asn")):
            row = matches.get(identifier)
            if row and row[field]:
                result["fields"][field] = row[field]
                result["field_sources"]["country" if field == "country_code" else field] = identifier
            else:
                incomplete = True
        if usable:
            result.update(status="ok", reason=None, partial=bool(incomplete))
        elif not self.error:
            result["reason"] = "no_usable_data"
        return result
