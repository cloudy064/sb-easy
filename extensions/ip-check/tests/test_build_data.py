import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("build_data", Path(__file__).parents[1] / "build_data.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class DataBuilderTests(unittest.TestCase):
    def lock(self, cache, body=b"1.0.0.0,1.0.0.255,AU\n2001:db8::,2001:db8::ffff,US\n"):
        (cache / "country.csv").write_bytes(body)
        sources = [{"id": key, "name": key, "url": "https://example.test/source", "license": "test-fixture",
                    "updated_at": "2026-10-01", "status": "missing", "inputs": []} for key in sorted(builder.SOURCE_IDS)]
        country = next(source for source in sources if source["id"] == "dbip-country")
        country.update(status="ready", format="country", inputs=[{"file": "country.csv", "url": "https://example.test/country.csv",
                                                                "sha256": hashlib.sha256(body).hexdigest()}])
        return {"version": 1, "sources": sources}

    def test_build_has_fixed_length_ranges_and_query_boundaries(self):
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder)
            output = cache / "output" / "ip-intelligence.sqlite"
            manifest = builder.build_database(self.lock(cache), cache, output, offline=True)
            self.assertEqual(manifest["sha256"], builder.digest_file(output))
            self.assertEqual(manifest["size_bytes"], output.stat().st_size)
            self.assertEqual(json.loads(output.with_name("manifest.json").read_text())["sha256"], manifest["sha256"])
            with closing(sqlite3.connect(output)) as db:
                self.assertEqual(db.execute("SELECT family,length(start),length(end) FROM ranges ORDER BY family").fetchall(), [(4, 4, 4), (6, 16, 16)])
                self.assertEqual(db.execute("SELECT families FROM sources WHERE id='dbip-country'").fetchone()[0], "4,6")
                self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='version'").fetchone()[0], "1")
                self.assertEqual(db.execute("SELECT COUNT(*) FROM sources WHERE status='missing'").fetchone()[0], 4)

    def test_overlapping_csv_preserves_previous_database_and_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder)
            output = cache / "output.sqlite"
            output.write_bytes(b"previous database")
            (cache / "manifest.json").write_bytes(b"previous manifest")
            lock = self.lock(cache, b"1.0.0.0,1.0.0.255,AU\n1.0.0.100,1.0.1.255,US\n")
            with self.assertRaisesRegex(ValueError, "overlapping"):
                builder.build_database(lock, cache, output, offline=True)
            self.assertEqual(output.read_bytes(), b"previous database")
            self.assertEqual((cache / "manifest.json").read_bytes(), b"previous manifest")
            self.assertFalse(list(cache.glob("*.building")))

    def test_download_cache_tamper_is_rejected_offline(self):
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder)
            lock = self.lock(cache)
            (cache / "country.csv").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "cached snapshot"):
                builder.build_database(lock, cache, cache / "out.sqlite", offline=True)

    def test_cidr_merges_overlap_and_adjacent_preserving_address_family(self):
        rows = list(builder.cidr_rows(io.StringIO("10.0.0.0/24\n10.0.0.128/25\n10.0.1.0/24\n2001:db8::/126\n2001:db8::4/126\n")))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][1:3], (bytes([10, 0, 0, 0]), bytes([10, 0, 1, 255])))
        self.assertEqual(rows[1][0], 6)
        self.assertEqual(len(rows[1][1]), 16)

    def test_csv_rejects_mixed_reversed_invalid_country_and_invalid_asn(self):
        for source, kind in [("1.0.0.0,::1,US\n", "country"), ("1.0.0.2,1.0.0.1,US\n", "country"),
                             ("1.0.0.0,1.0.0.1,USA\n", "country"), ("1.0.0.0,1.0.0.1,4294967296,Org\n", "asn")]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                list(builder.csv_rows(io.StringIO(source), kind))

    def test_tor_parses_only_observed_exit_addresses_and_deduplicates(self):
        text = "@type tordnsel 1.0\nExitNode " + "A" * 40 + "\nPublished 2026-10-13 01:00:00\nLastStatus 2026-10-13 02:00:00\n"
        text += "ExitAddress 8.8.8.8 2026-10-13 01:30:00\nExitAddress 8.8.8.8 2026-10-13 01:40:00\n"
        text += "ExitAddress 2606:4700:4700::1111 2026-10-13 01:40:00\n"
        rows = list(builder.tordnsel_rows(io.StringIO(text)))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0:3], (4, bytes([8, 8, 8, 8]), bytes([8, 8, 8, 8])))
        self.assertEqual(rows[1][0], 6)

    def test_tor_rejects_other_formats_private_ips_and_invalid_timestamps(self):
        for text in ("8.8.8.8\n", "@type tordnsel 2.0\n", "@type tordnsel 1.0\n",
                     "@type tordnsel 1.0\nExitAddress 127.0.0.1 2026-10-13 01:00:00\n",
                     "@type tordnsel 1.0\nExitAddress 8.8.8.8 2026-50-13 01:00:00\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                list(builder.tordnsel_rows(io.StringIO(text)))

    def test_empty_input_and_publisher_digest_mismatch_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "data.csv"
            for body, item in [(b"", {}), (b"content", {"decoded_sha1": "0" * 40})]:
                path.write_bytes(body)
                with self.assertRaises(ValueError), builder.decoded_input(path, item):
                    pass

    def test_expansion_is_bounded(self):
        import gzip
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "data.gz"
            path.write_bytes(gzip.compress(b"x" * 100))
            with patch.object(builder, "MAX_DECODED", 32), self.assertRaisesRegex(ValueError, "size limit"), builder.decoded_input(path, {"compression": "gzip"}):
                pass

    def test_download_rejects_digest_mismatch_without_replacing_existing_cache(self):
        class Response(io.BytesIO):
            status = 200
            headers = {"Content-Length": "3"}
        class Opener:
            def open(self, request, timeout):
                return Response(b"bad")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "snapshot.csv"
            path.write_bytes(b"old")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                builder.download("https://example.test/snapshot", path, "0" * 64, opener=Opener())
            self.assertEqual(path.read_bytes(), b"old")
            self.assertFalse(list(Path(folder).glob("*.part")))

    def test_download_bounds_unannounced_body(self):
        class Response(io.BytesIO):
            status = 200
            headers = {}
        class Opener:
            def open(self, request, timeout):
                return Response(b"x" * 10)
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "size/time"):
                builder.download("https://example.test/snapshot", Path(folder) / "snapshot", "0" * 64, opener=Opener(), max_bytes=5)

    def test_path_traversal_and_http_source_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder)
            lock = self.lock(cache)
            source = next(s for s in lock["sources"] if s["id"] == "dbip-country")
            source["inputs"][0]["file"] = "../outside"
            with self.assertRaisesRegex(ValueError, "filename"):
                builder.validate_lock(lock)
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                builder.download("http://example.test", cache / "file", "0" * 64)

    def test_bundled_snapshot_can_build_offline_without_network(self):
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder) / "cache"
            cache.mkdir()
            lock = self.lock(cache)
            source = next(s for s in lock["sources"] if s["id"] == "dbip-country")
            source["inputs"][0].update(bundled=True, retrieved_at="2026-10-13T00:00:00Z")
            bundled = Path(folder) / "snapshots"
            bundled.mkdir()
            (cache / "country.csv").replace(bundled / "country.csv")
            with patch.object(builder, "SNAPSHOT_DIR", bundled), patch.object(builder, "download", side_effect=AssertionError("network is forbidden")):
                manifest = builder.build_database(lock, cache, cache / "out.sqlite", offline=True)
            self.assertEqual(next(s for s in manifest["sources"] if s["id"] == "dbip-country")["retrieved_at"], "2026-10-13T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
