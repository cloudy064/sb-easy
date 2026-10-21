"""Daily, server-owned node measurements. No browser request starts a probe."""
from contextlib import closing
import copy
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from worker import Worker
from probe import SUPPORTED_NODES


def outbound(row):
    config = json.loads(row['protocol_config'])
    kind = row['node_type']
    fields = {
        'shadowsocks': ('method', 'password'),
        'vmess': ('uuid', 'alter_id', 'security', 'transport', 'tls'),
        'trojan': ('password', 'transport', 'tls'),
        'vless': ('uuid', 'flow', 'packet_encoding', 'transport', 'tls'),
        'hysteria2': ('password', 'tls', 'obfs'),
        'tuic': ('uuid', 'password', 'congestion_control', 'udp_relay_mode', 'tls'),
        'http': ('username', 'password', 'tls'),
    }
    result = {key: config[key] for key in fields.get(kind, ()) if key in config}
    defaults = {'vmess': {'alter_id': 0, 'security': 'auto'},
                'vless': {'flow': '', 'packet_encoding': 'xudp'},
                'tuic': {'congestion_control': 'bbr', 'udp_relay_mode': 'native'}}
    for key, value in defaults.get(kind, {}).items():
        result.setdefault(key, value)
    result.update(type=kind, tag=row['tag'], server=row['server'], server_port=row['server_port'])
    return result


class Daily:
    interval = 86400

    def __init__(self, directory, database, core, interface, data_dir, mark=None, clock=time.time):
        self.path = Path(directory) / 'daily-cache.json'
        self.database, self.core, self.interface = database, core, interface
        self.data_dir, self.mark, self.clock = data_dir, mark, clock
        self.records, self.inventory, self.active = {}, {}, None
        self.worker = None
        self.last_scan = 0
        self.error = ''
        try:
            if self.path.stat().st_size < 16 * 1024 * 1024:
                self.records = json.loads(self.path.read_text())['records']
        except (OSError, ValueError, KeyError):
            pass

    def scan(self):
        # Read-only connection: never modify the application's database.
        with closing(sqlite3.connect(Path(self.database).resolve().as_uri() + '?mode=ro', uri=True, timeout=1)) as db:
            db.row_factory = sqlite3.Row
            rows = db.execute('SELECT id,tag,node_type,enabled,server,server_port,protocol_config FROM proxy_nodes').fetchall()
        inventory = {}
        for row in rows:
            node = outbound(row)
            digest = hashlib.sha256(json.dumps(node, sort_keys=True).encode()).hexdigest()
            inventory[row['id']] = (digest, node, bool(row['enabled']))
        self.inventory = inventory
        self.records = {key: value for key, value in self.records.items()
                        if key in inventory and value.get('digest') == inventory[key][0]}

    def save(self):
        temporary = self.path.with_suffix('.tmp')
        temporary.write_text(json.dumps({'records': self.records}, ensure_ascii=False), encoding='utf-8')
        temporary.replace(self.path)

    def tick(self):
        now = self.clock()
        if now - self.last_scan >= 60:
            try:
                self.scan()
                self.error = ''
                self.last_scan = now
            except (OSError, sqlite3.Error, ValueError, TypeError):
                self.error = 'inventory_unavailable'
                self.last_scan = now
                return
        if self.worker:
            snapshot = self.worker.snapshot()
            if snapshot['phase'] == 'running':
                return
            key, digest = self.active
            result = snapshot['results'][0] if snapshot['results'] else {'status': 'unknown', 'reason': 'probe_runtime_failed'}
            if key in self.inventory and self.inventory[key][0] == digest:
                old = self.records.get(key, {})
                success = result.get('ipv4', {}).get('status') == 'ok' or result.get('ipv6', {}).get('status') == 'ok'
                self.records[key] = {'digest': digest, 'attempted_at': now, 'result': result,
                                     'last_success': result if success else old.get('last_success')}
                self.save()
            self.worker.close()
            self.worker, self.active = None, None
        if self.error:
            return
        for key, (digest, node, enabled) in self.inventory.items():
            if not enabled or node['type'] not in SUPPORTED_NODES:
                continue
            if now - self.records.get(key, {}).get('attempted_at', 0) < self.interval:
                continue
            self.worker = Worker(self.data_dir, self.mark)
            self.active = (key, digest)
            try:
                self.worker.start({'config': {'outbounds': [node]}, 'tags': [node['tag']],
                                   'ipv6': True, 'sing_box': self.core, 'interface': self.interface})
            except Exception:
                self.records[key] = {'digest': digest, 'attempted_at': now,
                                     'result': {'status': 'unknown', 'reason': 'invalid_node_configuration'}}
                self.worker.close()
                self.worker, self.active = None, None
                self.save()
            break

    def snapshot(self):
        def compact(result):
            if not result: return None
            result = copy.deepcopy(result)
            for family in ('ipv4', 'ipv6'):
                info = result.get(family, {}).get('ip_info')
                if info:
                    result[family]['ip_info'] = {key: info[key] for key in
                        ('status', 'fields', 'partial', 'database') if key in info}
            return result
        nodes = {}
        for key, (_, node, enabled) in self.inventory.items():
            record = self.records.get(key, {})
            result = record.get('result', {})
            status = 'ok' if any(result.get(f, {}).get('status') == 'ok' for f in ('ipv4', 'ipv6')) else 'failed'
            if not record: status = 'pending'
            if not enabled: status = 'disabled'
            elif node['type'] not in SUPPORTED_NODES: status = 'unsupported'
            elif self.active and self.active[0] == key: status = 'refreshing'
            nodes[key] = {'status': status, 'attempted_at': record.get('attempted_at'),
                          'next_check_at': record.get('attempted_at', 0) + self.interval if record else None,
                          'result': compact(result), 'last_success': compact(record.get('last_success')) if not any(result.get(f, {}).get('status') == 'ok' for f in ('ipv4', 'ipv6')) else None}
        return copy.deepcopy({'nodes': nodes, 'interval_seconds': self.interval, 'error': self.error,
                              'running': self.worker is not None, 'execution': 'center'})

    def for_config(self, config):
        # Match full protocol identity, never labels alone; device tokens only
        # see the nodes present in their server-rendered configuration.
        def identity(node):
            normalized = outbound({'protocol_config': json.dumps(node), 'node_type': node.get('type'),
                'tag': '', 'server': node.get('server'), 'server_port': node.get('server_port')})
            return json.dumps(normalized, sort_keys=True)
        snapshot = self.snapshot()
        by_identity = {identity(node): key for key, (_, node, _) in self.inventory.items()}
        allowed = {}
        for node in config.get('outbounds', []):
            if node.get('type') not in SUPPORTED_NODES or not isinstance(node.get('tag'), str): continue
            key = by_identity.get(identity(node))
            if key in snapshot['nodes']: allowed[node['tag']] = snapshot['nodes'][key]
        snapshot['nodes'] = allowed
        return snapshot

    def close(self):
        if self.worker: self.worker.close()
