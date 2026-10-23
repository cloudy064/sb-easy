"""Local mitmproxy engine used by the Windows worker.

No CA private key or captured body crosses the host/plugin control channel.
The authenticated mitmweb interface provides viewing, editing, replay and HAR.
"""
import asyncio
import json
import shutil
from pathlib import Path
import secrets
import threading


class SessionLimit:
    """Bound retained sessions; streamed bodies are explicitly absent in mitmweb."""
    def __init__(self, master):
        self.master = master

    def response(self, flow):
        self.prune()

    def error(self, flow):
        self.prune()

    def prune(self):
        view = self.master.view
        if view.store_count() > 500:
            removable = [f for f in view._store.values() if not f.live and not f.intercepted]
            view.remove(removable[:max(0, view.store_count() - 500)])


class Engine:
    def __init__(self):
        self.lock = threading.RLock()
        self.thread = None
        self.loop = None
        self.master = None
        self.phase = "stopped"
        self.error = ""
        self.token = ""
        self.password = ""
        self.directory = None
        self.proxy_port = 17990
        self.web_port = 17991
        self.upstream_port = 17992
        self.authenticated_upstream = False

    def start(self, directory, proxy_port=17990, web_port=17991, upstream_port=17992, authenticated_upstream=False):
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise ValueError("A capture session is already running")
            for port in (proxy_port, web_port, upstream_port):
                if not isinstance(port, int) or not 1024 <= port <= 65535:
                    raise ValueError("Invalid loopback port")
            if len({proxy_port, web_port, upstream_port}) != 3:
                raise ValueError("Ports must differ")
            if not isinstance(authenticated_upstream, bool):
                raise ValueError("Invalid upstream authentication option")
            self.authenticated_upstream = authenticated_upstream
            self.directory = Path(directory).resolve()
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.proxy_port, self.web_port, self.upstream_port = proxy_port, web_port, upstream_port
            self.token, self.password = secrets.token_hex(32), secrets.token_hex(32)
            self.phase, self.error = "starting", ""
            self.thread = threading.Thread(target=self._run, daemon=True, name="http-debug")
            self.thread.start()
            return self.snapshot()

    def _run(self):
        try:
            asyncio.run(self._serve())
        except BaseException as error:
            with self.lock:
                self.phase, self.error = "failed", str(error)[:500]
        finally:
            with self.lock:
                self.master = self.loop = None
                if self.phase != "failed":
                    self.phase = "stopped"

    async def _serve(self):
        # Imports stay in the engine thread: the Windows framed IPC must remain
        # responsive during cold Python/cryptography startup.
        from mitmproxy import options
        from mitmproxy.tools.web.master import WebMaster
        engine = self

        class Ready:
            async def running(self):
                with engine.lock:
                    engine.phase = "running"

        opts = options.Options(
            confdir=str(self.directory), listen_host="127.0.0.1",
            listen_port=self.proxy_port,
            mode=[f"upstream:http://127.0.0.1:{self.upstream_port}"],
            ssl_insecure=False,
        )
        master = WebMaster(opts)
        # The Windows worker is service-owned. Keep mitmweb's session editor,
        # but never expose its arbitrary script/path/process controls there.
        from mitmproxy.tools.web import app as webapp
        from mitmproxy.addons.savehar import SaveHar

        class SafeOptions(webapp.Options):
            def put(self):
                allowed = {"view_filter", "view_order", "view_order_reversed", "intercept", "intercept_active", "showhost"}
                if set(self.json) - allowed:
                    raise webapp.APIError(403, "This engine's network, certificate and script settings are managed by sb-easy.")
                super().put()

        class Disabled(webapp.RequestHandler):
            def get(self, **kwargs):
                raise webapp.APIError(403, "This operation is unavailable in the sb-easy plugin.")
            post = put = delete = get

        class ExportHar(webapp.RequestHandler):
            def get(self):
                self.set_header("Content-Disposition", 'attachment; filename="sb-easy-capture.har"')
                self.set_header("Content-Type", "application/json")
                self.write(SaveHar().make_har(list(self.view)))

        master.app.add_handlers(r".*", [
            (r"/options(?:\.json)?", SafeOptions),
            (r"/options/save", Disabled), (r"/commands(?:/.*|\.json)?", Disabled),
            (r"/processes", Disabled), (r"/executable-icon", Disabled),
            (r"/sbeasy.har", ExportHar),
        ])
        opts.update(web_host="127.0.0.1", web_port=self.web_port,
                    web_open_browser=False, web_password=self.token,
                    proxyauth=f"sbeasy:{self.password}",
                    stream_large_bodies="2m", body_size_limit="32m")
        if self.authenticated_upstream:
            opts.update(upstream_auth=f"sbeasy:{self.password}")
        master.addons.add(SessionLimit(master), Ready())
        with self.lock:
            self.loop, self.master = asyncio.get_running_loop(), master
        await master.run()

    def stop(self):
        with self.lock:
            master = self.master
            if master:
                master.shutdown()
            elif self.phase == "starting":
                raise ValueError("Engine is starting; retry stop shortly")
        if self.thread:
            self.thread.join(timeout=2)
        return self.snapshot()

    def snapshot(self):
        with self.lock:
            return dict(phase=self.phase, error=self.error,
                        url=f"http://127.0.0.1:{self.web_port}/?token={self.token}" if self.phase == "running" else "",
                        proxy_port=self.proxy_port, upstream_port=self.upstream_port,
                        username="sbeasy", password=self.password)

    def certificate(self):
        with self.lock:
            if self.phase != "running":
                raise ValueError("Start the engine before exporting its certificate")
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            cert = x509.load_pem_x509_certificate((self.directory / "mitmproxy-ca-cert.pem").read_bytes())
            return {"der": cert.public_bytes(serialization.Encoding.DER).hex()}


engine = Engine()


def dispatch(method, params):
    if method == "start":
        return engine.start(**params)
    if method == "snapshot":
        return engine.snapshot()
    if method == "stop":
        return engine.stop()
    if method == "certificate":
        return engine.certificate()
    raise ValueError("Unknown engine operation")


def android_call(method, params_json):
    """The signature-protected Android service owns the CA directory, never the host."""
    params = json.loads(params_json)
    if method == "start":
        params["authenticated_upstream"] = True
    if method in ("clear", "stop"):
        engine.stop()
        if engine.thread and engine.thread.is_alive():
            raise ValueError("Stop is still in progress; retry cleanup")
        directory = Path(params.get("directory") or engine.directory).resolve()
        if directory.exists():
            shutil.rmtree(directory)
        result = dict(phase="stopped")
    else:
        result = dispatch(method, params)
    result["protocol_version"] = 2
    return json.dumps(result)
