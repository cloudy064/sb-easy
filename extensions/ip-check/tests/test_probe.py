import copy
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from probe import ProbeCore, ProbeError, echo_ip, main, make_probe_config, probe_node, proxy_request, select_tags
from provider import MAX_RESPONSE_BYTES, ResponseTooLarge


def example():
    return {
        "inbounds": [{"type": "tun", "tag": "user-tun", "auto_route": True}],
        "outbounds": [
            {"type": "http", "tag": "node-a", "server": "a.example", "server_port": 443, "password": "private", "bind_interface": "user-tun", "detour": "transport"},
            {"type": "socks", "tag": "transport", "server": "192.0.2.1", "server_port": 1080},
            {"type": "http", "tag": "node-b", "server": "b.example", "server_port": 443},
            {"type": "urltest", "tag": "auto", "outbounds": ["node-a", "node-b"]},
            {"type": "selector", "tag": "dns-path", "outbounds": ["node-a", "node-b"], "default": "node-b"},
            {"type": "direct", "tag": "direct"},
        ],
        "dns": {"servers": [{"type": "https", "tag": "remote-dns", "server": "dns.example", "detour": "dns-path"}], "final": "remote-dns", "rules": [{"rule_set": "remote-rules", "server": "remote-dns"}]},
        "route": {"final": "direct", "rules": [{"domain_suffix": "ipify.org", "outbound": "direct"}], "rule_set": [{"tag": "remote-rules", "type": "remote"}], "default_domain_resolver": "remote-dns"},
        "experimental": {"clash_api": {"external_controller": "0.0.0.0:9090", "secret": "private"}},
        "ntp": {"enabled": True},
        "endpoints": [{"type": "wireguard", "tag": "wg"}],
    }


class RoutingTests(unittest.TestCase):
    def test_isolation_and_fixed_final_preserve_only_dependencies(self):
        source = example()
        before = copy.deepcopy(source)
        config = make_probe_config(source, "node-a", 12345, "probe", "random", "Wi-Fi")
        self.assertEqual(source, before)
        self.assertEqual(set(config), {"log", "inbounds", "outbounds", "route", "dns"})
        self.assertEqual(config["route"], {"final": "node-a", "default_interface": "Wi-Fi", "rules": [], "default_domain_resolver": "remote-dns"})
        self.assertEqual(config["inbounds"], [{"type": "http", "tag": "sb-easy-ip-check", "listen": "127.0.0.1", "listen_port": 12345, "users": [{"username": "probe", "password": "random"}]}])
        nodes = {node["tag"]: node for node in config["outbounds"]}
        self.assertEqual(set(nodes), {"node-a", "transport", "dns-path", "node-b"})
        self.assertEqual(nodes["dns-path"]["outbounds"], ["node-b"])
        self.assertEqual(nodes["node-a"]["detour"], "transport")
        self.assertEqual(nodes["node-a"]["bind_interface"], "Wi-Fi")
        self.assertEqual(nodes["transport"]["bind_interface"], "Wi-Fi")
        self.assertNotIn("rules", config["dns"])
        self.assertEqual(config["dns"]["servers"][0]["detour"], "dns-path")

    def test_no_direct_or_auto_selections_and_limit(self):
        source = example()
        self.assertEqual(select_tags(source, [], True, 2), ["node-a", "transport"])
        for tag in ["auto", "direct", "dns-path"]:
            with self.assertRaisesRegex(ProbeError, "concrete"):
                select_tags(source, [tag], False, 10)
        with self.assertRaisesRegex(ProbeError, "exceed"):
            select_tags(source, ["node-a", "node-b"], False, 1)
        with self.assertRaisesRegex(ProbeError, "missing"):
            select_tags(source, ["missing"], False, 10)

    def test_dynamic_missing_and_cyclic_dependencies_fail_closed(self):
        for detour, expected in [("auto", "urltest"), ("missing", "missing"), ("node-a", "cyclic")]:
            source = example()
            source["outbounds"][0]["detour"] = detour
            with self.assertRaisesRegex(ProbeError, expected):
                make_probe_config(source, "node-a", 12345, "p", "secret", "Wi-Fi")

    def test_explicit_dns_override_avoids_fake_ip_and_unrelated_nodes(self):
        config = make_probe_config(example(), "node-a", 12345, "p", "secret", "Wi-Fi", "223.5.5.5")
        self.assertEqual({n["tag"] for n in config["outbounds"]}, {"node-a", "transport"})
        self.assertEqual(config["dns"]["servers"], [{"type": "udp", "tag": "probe-bootstrap", "server": "223.5.5.5", "bind_interface": "Wi-Fi"}])
        self.assertEqual(config["route"]["default_domain_resolver"], "probe-bootstrap")
        self.assertTrue(all(n["domain_resolver"] == "probe-bootstrap" for n in config["outbounds"]))

    def test_interface_required_and_fakeip_default_rejected(self):
        with self.assertRaisesRegex(ProbeError, "interface"):
            make_probe_config(example(), "node-a", 12345, "p", "secret", "")
        source = example()
        source["dns"]["servers"].append({"type": "fakeip", "tag": "fake"})
        source["dns"]["final"] = "fake"
        with self.assertRaisesRegex(ProbeError, "fakeip"):
            make_probe_config(source, "node-a", 12345, "p", "secret", "Wi-Fi")


class EchoTests(unittest.TestCase):
    def setUp(self):
        self.core = MagicMock(port=12345, username="probe", password="secret")

    def test_https_tunnel_auth_never_environment_proxy(self):
        with patch("probe.http.client.HTTPSConnection") as cls, patch.dict("os.environ", {"NO_PROXY": "*", "HTTPS_PROXY": "http://bad.invalid"}):
            connection = cls.return_value
            connection.getresponse.return_value.status = 200
            connection.getresponse.return_value.read.return_value = b'{"ip":"8.8.8.8"}'
            self.assertEqual(echo_ip(self.core, 4), "8.8.8.8")
            cls.assert_called_once_with("127.0.0.1", 12345, timeout=15)
            connection.set_tunnel.assert_called_once_with("api.ipify.org", 443, headers={"Proxy-Authorization": "Basic cHJvYmU6c2VjcmV0"})
            self.assertNotIn("Proxy-Authorization", connection.request.call_args.kwargs["headers"])
            connection.close.assert_called_once()

    def test_failed_tunnel_has_no_fallback(self):
        with patch("probe.http.client.HTTPSConnection") as cls:
            cls.return_value.request.side_effect = OSError("secret information that must not be shown")
            with self.assertRaisesRegex(ProbeError, "^echo_connection_failed$"):
                echo_ip(self.core, 4)
            self.assertEqual(cls.call_count, 1)
            cls.return_value.close.assert_called_once()

    def test_reject_wrong_family_private_ip_bad_json_redirect_and_oversize(self):
        for response in [b'{"ip":"::1"}', b'{"ip":"1.1.1.1"}', b'{"ip":"192.168.0.2"}', b'{"ip":"ff02::1"}', b'not-json', b'x' * 4097]:
            with patch("probe.http.client.HTTPSConnection") as cls:
                cls.return_value.getresponse.return_value.status = 200
                cls.return_value.getresponse.return_value.read.return_value = response
                with self.assertRaises(ProbeError):
                    echo_ip(self.core, 6)
        with patch("probe.http.client.HTTPSConnection") as cls:
            cls.return_value.getresponse.return_value.status = 302
            with self.assertRaisesRegex(ProbeError, "http_error"):
                echo_ip(self.core, 4)

    def test_ipv6_host_and_validation(self):
        with patch("probe.http.client.HTTPSConnection") as cls:
            cls.return_value.getresponse.return_value.status = 200
            cls.return_value.getresponse.return_value.read.return_value = b'{"ip":"2606:4700:4700::1111"}'
            self.assertEqual(echo_ip(self.core, 6), "2606:4700:4700::1111")
            self.assertEqual(cls.return_value.set_tunnel.call_args.args, ("api6.ipify.org", 443))

    def test_metadata_and_non_echo_destinations_are_never_contacted(self):
        forbidden = ["https://iplark.com/demo/api?ip=1.1.1.1", "http://api.ipify.org/?format=json",
                     "https://api.ipify.org.evil/?format=json", "https://other.example/",
                     "https://api.ipify.org/?format=json&ip=1.1.1.1", "https://api.ipify.org:443/?format=json",
                     "https://api.ipify.org/path?format=json", "https://api.ipify.org/?format=json#fragment"]
        with patch("probe.http.client.HTTPSConnection") as cls:
            for url in forbidden:
                with self.assertRaises(OSError):
                    proxy_request(self.core, url)
            cls.assert_not_called()

    def test_provider_size_limit(self):
        with patch("probe.http.client.HTTPSConnection") as cls:
            cls.return_value.getresponse.return_value.status = 200
            cls.return_value.getresponse.return_value.read.return_value = b"x" * (MAX_RESPONSE_BYTES + 1)
            with self.assertRaises(ResponseTooLarge):
                proxy_request(self.core, "https://api.ipify.org/?format=json")
            cls.return_value.getresponse.return_value.read.assert_called_once_with(MAX_RESPONSE_BYTES + 1)
            cls.return_value.close.assert_called_once()

    def test_total_deadline_interrupts_slow_header_or_body_without_fallback(self):
        with patch("probe.http.client.HTTPSConnection") as cls, patch("probe.threading.Timer") as timer:
            connection = cls.return_value
            def stalled_request(*args, **kwargs):
                timer.call_args.args[1]()
                raise OSError("private response details")
            connection.request.side_effect = stalled_request
            with self.assertRaisesRegex(TimeoutError, "^probe_request_timeout$"):
                proxy_request(self.core, "https://api.ipify.org/?format=json", timeout=12)
            self.assertEqual(cls.call_count, 1)
            connection.sock.shutdown.assert_called_once()
            connection.sock.close.assert_called_once()
            timer.return_value.cancel.assert_called_once()


class LifecycleTests(unittest.TestCase):
    def test_cancel_stops_process_and_removes_credentials(self):
        created = []
        process = MagicMock()
        process.poll.return_value = None
        def start(command, **kwargs):
            path = Path(command[-1])
            created.append(path)
            self.assertTrue(path.is_file())
            self.assertNotIn("private", " ".join(command))
            self.assertEqual(json.loads(path.read_text())["inbounds"][0]["listen"], "127.0.0.1")
            return process
        with patch("probe.subprocess.Popen", side_effect=start), patch("probe.socket.create_connection"):
            core = ProbeCore("sing-box", example(), "node-a", "Wi-Fi")
            with self.assertRaises(KeyboardInterrupt):
                with core:
                    raise KeyboardInterrupt()
            self.assertFalse(created[0].exists())
            self.assertEqual(core.password, "")
            process.terminate.assert_called_once()

    def test_startup_failure_removes_temp_and_does_not_echo(self):
        with patch("probe.subprocess.Popen") as popen:
            popen.return_value.poll.return_value = 1
            core = ProbeCore("sing-box", example(), "node-a", "Wi-Fi")
            with self.assertRaisesRegex(ProbeError, "start_failed"):
                with core:
                    self.fail("failed process entered context")
            self.assertIsNone(core.directory)
            self.assertEqual(core.password, "")

    def test_duplicate_exits_share_lookup_and_failed_exit_never_looks_up(self):
        provider = MagicMock()
        provider.lookup.return_value = {"status": "ok", "country": "US"}
        cache = {}
        with patch("probe.ProbeCore"), patch("probe.echo_ip", return_value="8.8.8.8"):
            first = probe_node("sing-box", example(), "node-a", "Wi-Fi", provider, cache)
            second = probe_node("sing-box", example(), "node-b", "Wi-Fi", provider, cache)
        provider.lookup.assert_called_once_with("8.8.8.8")
        self.assertEqual(first["ipv4"]["ip_info"], second["ipv4"]["ip_info"])
        with patch("probe.ProbeCore"), patch("probe.echo_ip", side_effect=ProbeError("echo_connection_failed")):
            failed = probe_node("sing-box", example(), "node-a", "Wi-Fi", provider, cache, ipv6=True)
        self.assertEqual(provider.lookup.call_count, 1)
        self.assertEqual(failed["ipv6"]["status"], "unknown")
        self.assertNotIn("ip", failed["ipv4"])

    def test_default_metadata_is_offline_and_never_uses_probe_transport(self):
        with patch("probe.ProbeCore"), patch("probe.echo_ip", return_value="1.1.1.1"), patch("probe.proxy_request") as request, patch("probe.OfflineProvider") as provider:
            provider.return_value.__enter__.return_value.lookup.return_value = {"status":"ok", "partial":True}
            result = probe_node("sing-box", example(), "node-a", "Wi-Fi", None, {})
            provider.return_value.__enter__.return_value.lookup.assert_called_once_with("1.1.1.1")
            provider.return_value.__exit__.assert_called_once()
            request.assert_not_called()
            self.assertEqual(result["ipv4"]["ip_info"]["status"], "ok")


class SummaryTests(unittest.TestCase):
    def run_cli(self, results, ipv6=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.json"
            path.write_text(json.dumps(example()), encoding="utf-8")
            output_path = Path(directory) / "results.json"
            arguments = ["--config", str(path), "--sing-box", "unused", "--all", "--limit", "3",
                         "--interface", "Wi-Fi", "--output", str(output_path)] + (["--ipv6"] if ipv6 else [])
            stdout = io.StringIO()
            with patch("probe.probe_node", side_effect=results), contextlib.redirect_stdout(stdout):
                code = main(arguments)
            output = json.loads(stdout.getvalue())
            self.assertEqual(output, json.loads(output_path.read_text(encoding="utf-8")))
            return code, output["summary"]

    def test_exit_codes_distinguish_complete_blocked_metadata_and_failed_measurements(self):
        good = {"ipv4": {"status": "ok", "ip": "1.1.1.1", "ip_info": {"status": "ok"}}}
        blocked = {"ipv4": {"status": "ok", "ip": "1.1.1.1", "ip_info": {"status": "unknown", "http_status": 403, "reason": "blocked"}}}
        failed = {"ipv4": {"status": "unknown", "reason": "echo_connection_failed"}}
        for results, expected_code, expected_status, measured, info, complete in [
                ([good, good, good], 0, "complete", 3, 3, 3),
                ([blocked, blocked, blocked], 3, "partial", 3, 0, 0),
                ([good, blocked, failed], 3, "partial", 2, 1, 1),
                ([failed, failed, failed], 1, "failed", 0, 0, 0)]:
            with self.subTest(status=expected_status, measured=measured, info=info):
                code, summary = self.run_cli(results)
                self.assertEqual(code, expected_code)
                self.assertEqual(summary, {"status": expected_status, "node_count": 3, "processed_count": 3,
                                           "measured_count": measured, "info_count": info, "complete_count": complete})

    def test_requested_ipv6_missing_or_unknown_metadata_is_partial(self):
        ipv4 = {"status": "ok", "ip": "1.1.1.1", "ip_info": {"status": "ok"}}
        ipv6 = {"status": "ok", "ip": "2606:4700:4700::1111", "ip_info": {"status": "ok"}}
        results = [{"ipv4": ipv4}, {"ipv4": ipv4, "ipv6": ipv6},
                   {"ipv4": ipv4, "ipv6": dict(ipv6, ip_info={"status": "unknown"})}]
        code, summary = self.run_cli(results, ipv6=True)
        self.assertEqual(code, 3)
        self.assertEqual(summary["status"], "partial")
        self.assertEqual(summary["info_count"], 3)
        self.assertEqual(summary["complete_count"], 1)
        code, summary = self.run_cli([{"ipv4": ipv4, "ipv6": ipv6}] * 3, ipv6=True)
        self.assertEqual(code, 0)
        self.assertEqual(summary["status"], "complete")

    def test_empty_all_selection_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.json"
            path.write_text('{"outbounds": [{"type":"direct","tag":"direct"}]}')
            stderr = io.StringIO()
            with patch("probe.probe_node") as run, contextlib.redirect_stderr(stderr):
                code = main(["--config", str(path), "--sing-box", "unused", "--all", "--interface", "Wi-Fi"])
            self.assertEqual(code, 2)
            self.assertIn("select_at_least_one_node", stderr.getvalue())
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
