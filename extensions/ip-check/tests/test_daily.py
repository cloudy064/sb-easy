from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from daily import Daily

class FakeWorker:
    def __init__(self, *_): self.phase = 'running'
    def start(self, params): self.params = params
    def snapshot(self):
        return {'phase': self.phase, 'results': [{'checked_at': '2026-10-13T00:00:00Z',
            'ipv4': {'status': 'ok', 'ip': '8.8.8.8'}}] if self.phase == 'complete' else []}
    def close(self): pass

class DailyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'nodes.db'
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE proxy_nodes(id,tag,node_type,enabled,server,server_port,protocol_config)')
            db.execute('INSERT INTO proxy_nodes VALUES(?,?,?,?,?,?,?)',
                ('one', 'Node', 'http', 1, 'example.com', 443, json.dumps({'password': 'secret-fixture'})))
        self.now = 1000000
        self.make = lambda: Daily(self.tmp.name, str(self.db), '/core', 'eth0', '/data', clock=lambda: self.now)

    @patch('daily.Worker', FakeWorker)
    def test_automatic_due_restart_and_credentials_not_saved(self):
        daily = self.make(); daily.tick()
        self.assertEqual(daily.snapshot()['nodes']['one']['status'], 'refreshing')
        daily.worker.phase = 'complete'; daily.tick()
        self.assertEqual(daily.snapshot()['nodes']['one']['status'], 'ok')
        self.assertNotIn('secret-fixture', daily.path.read_text())
        restored = self.make(); restored.tick()
        self.assertIsNone(restored.worker)
        self.now += 86400; restored.tick()
        self.assertIsNotNone(restored.worker)

    @patch('daily.Worker', FakeWorker)
    def test_device_cache_matches_protocol_identity_and_filters_other_nodes(self):
        daily = self.make(); daily.tick(); daily.worker.phase = 'complete'; daily.tick()
        node = {'tag': '[Subscription] Node', 'type': 'http', 'server': 'example.com', 'server_port': 443, 'password': 'secret-fixture'}
        result = daily.for_config({'outbounds': [node]})
        self.assertEqual(set(result['nodes']), {'[Subscription] Node'})
        self.assertNotIn('secret-fixture', json.dumps(result))
        self.assertEqual(daily.for_config({'outbounds': []})['nodes'], {})
        node['password'] = 'different-account'
        self.assertEqual(daily.for_config({'outbounds': [node]})['nodes'], {})

    @patch('daily.Worker', FakeWorker)
    def test_configuration_change_invalidates_and_disabled_skipped(self):
        daily = self.make(); daily.tick(); daily.worker.phase = 'complete'; daily.tick()
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("UPDATE proxy_nodes SET server='changed.example', enabled=0")
        self.now += 61; daily.tick()
        self.assertEqual(daily.snapshot()['nodes']['one']['status'], 'disabled')
        self.assertIsNone(daily.snapshot()['nodes']['one']['result'])
        self.assertIsNone(daily.worker)

    @patch('daily.Worker', FakeWorker)
    def test_failure_retains_last_success_and_does_not_retry_loop(self):
        daily = self.make(); daily.tick(); daily.worker.phase = 'complete'; daily.tick()
        self.now += 86401; daily.tick(); daily.worker.phase = 'failed'; daily.tick()
        result = daily.snapshot()['nodes']['one']
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['last_success']['ipv4']['ip'], '8.8.8.8')
        daily.tick(); self.assertIsNone(daily.worker)
