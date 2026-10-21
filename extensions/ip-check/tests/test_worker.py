import copy
import contextlib
import io
import json
from pathlib import Path
import struct
import sys
import threading
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from probe import ProbeControl, ProbeCancelled, ProbeError
from worker import MAX_FRAME_BYTES, Worker, serve
from offline_provider import OfflineProvider
from test_provider import database, add_range, NOW


def parameters():
    return {"config": {"outbounds": [
        {"type": "http", "tag": "one", "server": "private.invalid", "password": "private-password"},
        {"type": "http", "tag": "two", "server": "private.invalid"}]},
        "sing_box": str(Path(sys.executable).resolve()), "tags": ["one", "two"],
        "interface": "fixture", "ipv6": False, "bootstrap_dns": "223.5.5.5"}


def wait_done(worker):
    deadline = time.monotonic() + 3
    while worker.snapshot()["phase"] == "running" and time.monotonic() < deadline:
        time.sleep(.005)
    state = worker.snapshot()
    assert state["phase"] != "running", state
    return state


class WorkerTests(unittest.TestCase):
    def test_hundred_dual_stack_results_retain_attribution_within_public_pipe_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.closing(database(directory)) as db:
                for ip in ("8.8.8.8", "2606:4700::1"):
                    add_range(db,"dbip-country",ip,country="US")
                    add_range(db,"dbip-asn",ip,asn=15169,organization="Fixture network")
            params = parameters()
            params["ipv6"] = True
            params["tags"] = [str(i).zfill(3) + "n"*253 for i in range(100)]
            params["config"]["outbounds"] = [{"type":"http", "tag":tag, "server":"fixture.invalid"} for tag in params["tags"]]
            def run(executable, source, tag, interface, provider, *args, **kwargs):
                return {"node":tag, "ipv6_requested":True,
                        "ipv4":{"status":"ok", "ip":"8.8.8.8", "ip_info":provider.lookup("8.8.8.8")},
                        "ipv6":{"status":"ok", "ip":"2606:4700::1", "ip_info":provider.lookup("2606:4700::1")}}
            worker = Worker()
            with patch("worker.OfflineProvider", side_effect=lambda:OfflineProvider(directory,NOW)), patch("worker.probe_node", side_effect=run):
                worker.start(params)
                state = wait_done(worker)
                worker.close()
            self.assertEqual(state["summary"]["complete_count"],100)
            self.assertLess(len(json.dumps(state, ensure_ascii=False).encode("utf-8")),768*1024)
            for result, tag in zip(state["results"],params["tags"]):
                self.assertEqual(result["node"],tag)
                self.assertEqual(len(result["ipv6"]["ip_info"]["sources"]),5)

    def test_offline_database_loaded_once_per_batch_and_closed_after_cancel_or_success(self):
        worker = Worker()
        with patch("worker.OfflineProvider") as provider, patch("worker.probe_node", return_value={"ipv4":{"status":"unknown"}}) as probe:
            worker.start(parameters())
            wait_done(worker)
            worker.close()
            provider.assert_called_once_with()
            provider.return_value.close.assert_called_once_with()
            self.assertEqual(probe.call_count, 2)
            self.assertTrue(all(call.args[4] is provider.return_value for call in probe.call_args_list))

    def test_start_snapshot_cancel_are_responsive_and_stop_private_child(self):
        entered = threading.Event()
        child = MagicMock()
        child.poll.return_value = None
        def run(*args, control, **kwargs):
            control.attach(child)
            entered.set()
            control.event.wait(2)
            control.check()
        worker = Worker()
        source = parameters()
        original = copy.deepcopy(source)
        with patch("worker.probe_node", side_effect=run):
            start = time.monotonic()
            self.assertEqual(worker.start(source)["phase"], "running")
            self.assertLess(time.monotonic() - start, .5)
            self.assertTrue(entered.wait(1))
            with self.assertRaisesRegex(ProbeError, "already_running"):
                worker.start(source)
            self.assertEqual(worker.snapshot()["results"], [])
            start = time.monotonic()
            self.assertTrue(worker.cancel()["cancel_requested"])
            self.assertLess(time.monotonic() - start, .5)
            self.assertEqual(wait_done(worker)["phase"], "cancelled")
        child.terminate.assert_called_once()
        self.assertEqual(source, original)
        worker.close()

    def test_partial_result_progress_and_blocked_is_never_clean(self):
        worker = Worker()
        second = threading.Event()
        release = threading.Event()
        def run(executable, source, tag, *args, **kwargs):
            if tag == "two":
                second.set()
                release.wait(2)
            return {"node": tag, "ipv4": {"status": "ok", "ip": "1.1.1.1",
                "ip_info": {"status": "unknown", "reason": "blocked", "http_status": 403}}}
        with patch("worker.probe_node", side_effect=run):
            worker.start(parameters())
            self.assertTrue(second.wait(1))
            state = worker.snapshot()
            self.assertEqual(state["phase"], "running")
            self.assertEqual(state["summary"]["processed_count"], 1)
            self.assertEqual(state["summary"]["info_count"], 0)
            # Returned snapshots do not expose mutable internal state.
            state["results"].clear()
            self.assertEqual(len(worker.snapshot()["results"]), 1)
            release.set()
            state = wait_done(worker)
            self.assertEqual(state["phase"], "partial")
            self.assertEqual(state["summary"]["measured_count"], 2)
            self.assertNotIn("private-password", json.dumps(state))
        worker.close()

    def test_sensitive_exception_is_redacted_and_worker_can_restart(self):
        worker = Worker()
        with patch("worker.probe_node", side_effect=RuntimeError("private-password private.invalid secretpath")):
            worker.start(parameters())
            state = wait_done(worker)
            self.assertEqual(state["error"], "probe_runtime_failed")
            self.assertNotIn("private", json.dumps(state))
        with patch("worker.probe_node", return_value={"ipv4": {"status": "unknown"}}):
            worker.start(parameters())
            state = wait_done(worker)
            self.assertEqual(state["phase"], "failed")
            self.assertEqual(len(state["results"]), 2)
        worker.close()

    def test_bad_input_never_starts_child(self):
        invalid = [("tags", []), ("tags", ["one"] * 101), ("tags", [1]),
                   ("tags", ["bad\nname"]), ("sing_box", "relative.exe"), ("interface", " "),
                   ("interface", "bad\tinterface"), ("interface", "界" * 86), ("ipv6", "yes"),
                   ("bootstrap_dns", "https://secret.invalid"), ("config", [])]
        with patch("worker.probe_node") as run:
            for key, value in invalid:
                with self.subTest(key=key, value=value):
                    params = parameters()
                    params[key] = value
                    with self.assertRaises(ProbeError):
                        Worker().start(params)
            run.assert_not_called()

    def test_full_tag_identity_preserved_with_native_utf8_byte_limit(self):
        for tag in ("n" * 256, "节点" * 42):
            params = parameters()
            params["config"]["outbounds"][0]["tag"] = tag
            params["tags"] = [tag]
            worker = Worker()
            def run(executable, source, actual_tag, *args, **kwargs):
                self.assertEqual(actual_tag, tag)
                return {"node": actual_tag, "ipv4": {"status": "unknown"}}
            with patch("worker.probe_node", side_effect=run):
                worker.start(params)
                self.assertEqual(wait_done(worker)["results"][0]["node"], tag)
            worker.close()
        params["tags"] = ["节点" * 43]
        with self.assertRaisesRegex(ProbeError, "invalid_node_selection"):
            Worker().start(params)

    def test_control_cancel_before_child_registration_stops_it(self):
        control = ProbeControl()
        control.cancel()
        child = MagicMock()
        child.poll.return_value = None
        with self.assertRaises(ProbeCancelled):
            control.attach(child)
        child.terminate.assert_called_once()

    def test_oversized_intelligence_becomes_unknown_with_echo_retained(self):
        worker = Worker()
        result = {"node": "one", "ipv4": {"status": "ok", "ip": "1.1.1.1",
                  "ip_info": {"status": "ok", "fields": {"data": "x" * 15000}}}}
        with patch("worker.probe_node", side_effect=lambda *a, **kw: copy.deepcopy(result)):
            worker.start(parameters())
            state = wait_done(worker)
        self.assertEqual(state["phase"], "partial")
        self.assertEqual(state["results"][0]["ipv4"]["ip_info"]["reason"], "response_too_large")
        self.assertEqual(state["results"][0]["ipv4"]["ip"], "1.1.1.1")

    def test_local_partial_data_preserves_info_count_without_complete_claim(self):
        worker = Worker()
        result = {"node":"one", "ipv4":{"status":"ok", "ip":"1.1.1.1", "ip_info":{"status":"ok", "partial":True}}}
        with patch("worker.probe_node", return_value=result):
            worker.start(parameters())
            state = wait_done(worker)
        self.assertEqual(state["phase"], "partial")
        self.assertEqual(state["summary"]["info_count"], 2)
        self.assertEqual(state["summary"]["complete_count"], 0)


class FramingTests(unittest.TestCase):
    def test_frames_validate_and_eof_cleans_up(self):
        values = [b'{"method":"snapshot"}', b'not-json', b'[]', b'{"method":"arbitrary-command"}']
        stream = io.BytesIO(b"".join(struct.pack("<I", len(item)) + item for item in values))
        output = io.BytesIO()
        worker = Worker()
        with patch.object(worker, "close", wraps=worker.close) as close:
            serve(stream, output, worker)
            close.assert_called_once()
        output.seek(0)
        answers = []
        for _ in values:
            size, = struct.unpack("<I", output.read(4))
            answers.append(json.loads(output.read(size)))
        self.assertEqual(answers[0]["result"]["phase"], "idle")
        self.assertEqual([r["message"] for r in answers[1:]], ["invalid_request", "invalid_request", "unsupported_method"])

    def test_oversized_or_incomplete_frame_exits_without_allocation(self):
        for data in [struct.pack("<I", MAX_FRAME_BYTES + 1), b'\x10', struct.pack("<I", 20) + b'{}']:
            worker = MagicMock()
            output = io.BytesIO()
            serve(io.BytesIO(data), output, worker)
            worker.dispatch.assert_not_called()
            worker.close.assert_called_once()
            self.assertEqual(output.getvalue(), b"")


if __name__ == "__main__":
    unittest.main()
