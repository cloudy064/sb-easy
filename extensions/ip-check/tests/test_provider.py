"""Offline lookup boundaries and absence/staleness are not clean verdicts."""
from datetime import datetime, timezone
import contextlib
import hashlib
import ipaddress
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from offline_provider import DATABASE_NAME, OfflineProvider, SOURCES
from provider import public_ip

NOW = datetime(2026, 10, 13, 12, tzinfo=timezone.utc)
CURRENT = NOW.isoformat()


def database(directory):
    db = sqlite3.connect(Path(directory) / DATABASE_NAME)
    db.executescript('''
      CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);
      CREATE TABLE sources(id TEXT PRIMARY KEY,name,url,license,updated_at,retrieved_at,status,families);
      CREATE TABLE ranges(source_id TEXT,family INTEGER,start BLOB,end BLOB,country_code TEXT,asn INTEGER,organization TEXT,network TEXT,
        PRIMARY KEY(source_id,family,start)) WITHOUT ROWID;
    ''')
    db.executemany("INSERT INTO metadata VALUES (?,?)", [("version", "1"), ("generated_at", CURRENT)])
    for identifier, (name, url, license_name, _) in SOURCES.items():
        db.execute("INSERT INTO sources VALUES (?,?,?,?,?,?,?,?)", (identifier,name,url,license_name,CURRENT,CURRENT,"ready","4,6"))
    db.commit()
    return db


def add_range(db, source, start, end=None, country=None, asn=None, organization=None, network=None):
    address = ipaddress.ip_address(start)
    db.execute("INSERT INTO ranges VALUES (?,?,?,?,?,?,?,?)", (source, address.version, address.packed,
        ipaddress.ip_address(end or start).packed, country, asn, organization, network))
    db.commit()


def manifest(directory):
    path = Path(directory) / DATABASE_NAME
    value = {"version":1, "file": DATABASE_NAME, "size_bytes":path.stat().st_size,
             "sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
    (Path(directory) / "manifest.json").write_text(json.dumps(value), encoding="utf-8")


class OfflineTests(unittest.TestCase):
    def test_public_literals_only(self):
        self.assertEqual(public_ip("2606:4700:4700:0:0:0:0:1111"), "2606:4700:4700::1111")
        for ip in ("localhost", "1.1.1.1 ", "https://1.1.1.1", "127.0.0.1", "10.1.2.3", "::1", "ff02::1", "fe80::1%3", None):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                public_ip(ip)

    def test_inclusive_v4_v6_boundaries_and_gaps(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.closing(database(directory)) as db:
                add_range(db,"dbip-country","8.8.8.1","8.8.8.4",country="US")
                add_range(db,"dbip-country","8.8.8.8","8.8.8.9",country="JP")
                add_range(db,"dbip-country","2606:4700::1","2606:4700::ffff",country="SG")
                add_range(db,"dbip-asn","8.8.8.1","8.8.8.9",asn=15169,organization="Fixture org")
            with OfflineProvider(directory, NOW) as provider:
                for ip, expected in (("8.8.8.1","US"),("8.8.8.4","US"),("8.8.8.5",None),("8.8.8.8","JP"),
                                     ("2606:4700::1","SG"),("2606:4700::ffff","SG"),("2606:4700::1:0",None)):
                    with self.subTest(ip=ip):
                        result=provider.lookup(ip)
                        self.assertEqual(result["fields"]["country_code"],expected)
                self.assertEqual(provider.lookup("8.8.8.1")["fields"]["asn"],"AS15169")
                self.assertEqual(provider.lookup("8.8.8.1")["field_sources"],
                    {"country":"dbip-country","asn":"dbip-asn","organization":"dbip-asn"})

    def test_negative_list_hit_never_becomes_false_or_residential(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.closing(database(directory)) as db:
                add_range(db,"x4b-datacenter","8.8.8.0","8.8.8.255",network="8.8.8.0/24")
            with OfflineProvider(directory, NOW) as provider:
                result=provider.lookup("8.8.8.8")
                self.assertEqual(result["fields"]["privacy"],{"is_datacenter":True,"is_vpn":None,"is_tor":None})
                checks={item["id"]:item for item in result["checks"]}
                self.assertEqual(checks["datacenter"]["status"],"listed")
                self.assertEqual(checks["datacenter"]["network"],"8.8.8.0/24")
                self.assertEqual(checks["vpn"]["status"],"not_listed")
                self.assertTrue(result["partial"])

    def test_complete_requires_expected_sources_family_and_geo_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.closing(database(directory)) as db:
                add_range(db,"dbip-country","8.8.8.8",country="US")
                add_range(db,"dbip-asn","8.8.8.8",asn=15169,organization="Fixture")
            with OfflineProvider(directory, NOW) as provider:
                self.assertFalse(provider.lookup("8.8.8.8")["partial"])

    def test_stale_missing_and_unsupported_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.closing(database(directory)) as db:
                db.execute("UPDATE sources SET updated_at='2026-09-01' WHERE id='x4b-datacenter'")
                db.execute("UPDATE sources SET families='4' WHERE id='x4b-vpn'")
                db.execute("DELETE FROM sources WHERE id='tor-exit'")
                db.commit()
                add_range(db,"x4b-datacenter","2606:4700::1",network="2606:4700::1/128")
            with OfflineProvider(directory, NOW) as provider:
                result=provider.lookup("2606:4700::1")
                self.assertEqual({check["id"]:check["status"] for check in result["checks"]},
                                 {"datacenter":"stale","vpn":"unsupported","tor":"unavailable"})
                self.assertTrue(result["partial"])
                self.assertTrue(result["fields"]["privacy"]["is_datacenter"])

    def test_missing_corrupt_and_bad_schema_do_not_create_files_or_make_requests(self):
        with tempfile.TemporaryDirectory() as directory, patch("socket.socket") as network:
            with OfflineProvider(directory, NOW) as provider:
                result=provider.lookup("1.1.1.1")
                self.assertEqual(result["reason"],"database_missing")
                self.assertNotIn("database",result)
            self.assertEqual(list(Path(directory).iterdir()),[])
            file=Path(directory)/DATABASE_NAME
            file.write_bytes(b"broken database")
            with OfflineProvider(directory, NOW) as provider:
                self.assertEqual(provider.lookup("1.1.1.1")["reason"],"database_invalid")
            file.unlink()
            with sqlite3.connect(file) as db:
                db.execute("CREATE TABLE wrong(x)")
            db.close()
            with OfflineProvider(directory, NOW) as provider:
                self.assertEqual(provider.lookup("1.1.1.1")["reason"],"database_invalid")
            network.assert_not_called()

    def test_manifest_mismatch_fails_closed_before_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.closing(database(directory)):
                pass
            manifest(directory)
            with OfflineProvider(directory, NOW) as provider:
                self.assertEqual(provider.lookup("1.1.1.1")["status"],"ok")
            file=Path(directory)/DATABASE_NAME
            with file.open("r+b") as stream:
                stream.seek(-1,2)
                stream.write(b"\xff")
            with OfflineProvider(directory, NOW) as provider:
                self.assertEqual(provider.lookup("1.1.1.1")["reason"],"database_invalid")

    def test_invalid_range_marks_source_unavailable_not_negative(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.closing(database(directory)) as db:
                add_range(db,"x4b-vpn","8.8.8.8")
                db.execute("UPDATE ranges SET end=x'00' WHERE source_id='x4b-vpn'")
                db.commit()
            with OfflineProvider(directory, NOW) as provider:
                result=provider.lookup("8.8.8.8")
                self.assertEqual(next(c for c in result["checks"] if c["id"]=="vpn")["status"],"unavailable")
                self.assertIsNone(result["fields"]["privacy"]["is_vpn"])

    def test_batch_connection_is_read_only_and_queries_do_not_mutate_data(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.closing(database(directory)):
                pass
            manifest(directory)
            file=Path(directory)/DATABASE_NAME
            before=file.read_bytes()
            with OfflineProvider(directory, NOW) as provider, patch("socket.socket") as network:
                with self.assertRaises(sqlite3.OperationalError):
                    provider.connection.execute("DELETE FROM sources")
                provider.lookup("1.1.1.1")
                provider.lookup("8.8.8.8")
                network.assert_not_called()
            self.assertIsNone(provider.connection)
            self.assertEqual(file.read_bytes(),before)


if __name__ == "__main__":
    unittest.main()
