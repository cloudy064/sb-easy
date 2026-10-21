"""Center-owned IP checks. Private Unix socket; authenticated C routes resolve nodes.

No desktop configuration or credentials are accepted by the public API. Result
snapshots are shared by profile + node-configuration digest and survive restart.
The center supervises one independent sing-box probe at a time.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import signal
import socketserver
import threading
from http.server import BaseHTTPRequestHandler
from probe import SUPPORTED_NODES, ProbeError
from worker import Worker
from daily import Daily


class Center:
    def __init__(self, directory, core, interface, data_dir, routing_mark=None):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.core, self.interface, self.data_dir = core, interface, data_dir
        self.routing_mark = routing_mark
        self.lock = threading.Lock()
        self.jobs = {}
        self.saved_digests = {}
        self.daily = None

    def dispatch(self, request):
        if request.get('action') == 'daily-device':
            return self.daily.for_config(request.get('config',{})) if self.daily else {'nodes': {}, 'error': 'scheduler_unavailable', 'running': False, 'interval_seconds': 86400}
        if request.get('action') == 'daily':
            return self.daily.snapshot() if self.daily else {'nodes': {}, 'error': 'scheduler_unavailable'}
        action, config, scope = request['action'], request['config'], request['scope']
        nodes = config.get('outbounds', [])
        if not isinstance(scope, str) or not scope or len(scope)>256 or not isinstance(nodes,list) or len(nodes)>2048:
            raise ValueError('invalid_scope')
        fingerprint = hashlib.sha256(json.dumps(nodes, sort_keys=True, separators=(',',':')).encode()).hexdigest()
        key = hashlib.sha256((scope+':'+fingerprint).encode()).hexdigest()
        if action == 'catalog':
            sources={tag:s['name'] for s in request.get('sources',[]) for tag in s.get('tags',[])}
            return {'nodes':[{'tag':n['tag'],'type':n['type'],'source':sources.get(n['tag'],'中心配置')}
                             for n in nodes if n.get('type') in SUPPORTED_NODES and isinstance(n.get('tag'),str)],
                    'interfaces':[], 'default_interface':'', 'execution':'center'}
        with self.lock:
            job = self.jobs.get(key)
            if action == 'start':
                if self.daily:
                    raise ValueError('automatic_daily_checks_enabled')
                params = request.get('params',{})
                if set(params)!={'tags','ipv6'}:
                    raise ValueError('invalid_start_parameters')
                if any(j.snapshot()['phase']=='running' for j in self.jobs.values()):
                    raise ValueError('center_check_already_running')
                if len(self.jobs)>=32:
                    self.jobs.pop(next(iter(self.jobs))).close()
                job=Worker(self.data_dir,self.routing_mark)
                job.start({'config':{'outbounds':nodes},'tags':params['tags'],'ipv6':params['ipv6'],
                           'sing_box':self.core,'interface':self.interface})
                self.jobs[key]=job
            elif action not in ('snapshot','cancel'):
                raise ValueError('unsupported_method')
            if job:
                result=job.cancel() if action=='cancel' else job.snapshot()
                # Never persist credentials/config: result contains only labels,
                # measured exits and attributed IP information.
                self.save(key,result)
            else:
                path=self.directory/(key+'.json')
                result=json.loads(path.read_text()) if path.is_file() and path.stat().st_size<900*1024 else Worker().snapshot()
                if result['phase']=='running':
                    result['phase']='failed';result['error']='center_restarted'
            return dict(result,execution='center',scope=scope)

    def save(self,key,result):
        payload=json.dumps(result,ensure_ascii=False).encode()
        if len(payload)>900*1024:
            raise ValueError('result_too_large')
        digest=hashlib.sha256(payload).digest()
        if self.saved_digests.get(key)==digest:
            return
        temporary=self.directory/(key+'.tmp')
        temporary.write_bytes(payload)
        temporary.replace(self.directory/(key+'.json'))
        self.saved_digests[key]=digest
        # Bound obsolete config snapshots. Current jobs are at most32.
        files=sorted((p for p in self.directory.glob('*.json') if p.name != 'daily-cache.json'),key=lambda p:p.stat().st_mtime)
        for old in files[:-128]:
            old.unlink()

    def checkpoint(self):
        if self.daily: self.daily.tick()
        with self.lock:
            for key,job in self.jobs.items():
                self.save(key,job.snapshot())

    def close(self):
        if self.daily: self.daily.close()
        with self.lock:
            for key,job in self.jobs.items():
                job.close();self.save(key,job.snapshot())


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def do_POST(self):
        self.connection.settimeout(10)
        try:
            size=int(self.headers.get('Content-Length','0'))
            if self.path!='/' or not 0<size<=2*1024*1024: raise ValueError('invalid_request')
            result=self.server.center.dispatch(json.loads(self.rfile.read(size)))
            body=json.dumps(result,ensure_ascii=False).encode();status=200
        except (ValueError,KeyError,TypeError,ProbeError):
            body=b'{"error":"Invalid request or another center check is running"}';status=409
        except Exception:
            body=b'{"error":"Center IP check unavailable"}';status=503
        self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)


def main():
    os.umask(0o077)
    path=Path(os.environ.get('IPCHECK_SOCKET','/run/sb-easy/ipcheck.sock'))
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if path.exists(): path.unlink()
    mark=os.environ.get('IPCHECK_ROUTING_MARK','')
    mark=int(mark,0) if mark else None
    if mark is not None and not 0<mark<=0xffffffff:
        raise ValueError('invalid_center_routing_mark')
    center=Center('/app/data/ipcheck-results',os.environ.get('IPCHECK_CORE','/usr/local/bin/sing-box'),
                  os.environ.get('IPCHECK_INTERFACE','eth0'),'/usr/share/sb-easy/ip-check/data',mark)
    center.daily=Daily(center.directory,os.environ.get('IPCHECK_DATABASE','/app/data/sb-easy.db'),
                       center.core,center.interface,center.data_dir,mark)
    server=socketserver.UnixStreamServer(str(path),Handler);server.center=center
    server.timeout=1
    stopped=threading.Event()
    for sig in (signal.SIGTERM,signal.SIGINT): signal.signal(sig,lambda *_:stopped.set())
    try:
        while not stopped.is_set():
            server.handle_request();center.checkpoint()
    finally:
        center.close();server.server_close();path.unlink(missing_ok=True)


if __name__=='__main__':main()
