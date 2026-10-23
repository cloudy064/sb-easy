#!/usr/bin/env python3
"""Host-only boundary tests for the Android acceptance driver."""
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("android_acceptance", Path(__file__).with_name("android-device-acceptance.py"))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class AcceptanceDriverTest(unittest.TestCase):
    def test_addresses_cannot_bind_public_or_wildcard_interfaces(self):
        for address in ("0.0.0.0", "8.8.8.8", "localhost", "::1", "127.0.0.1", "172.19.0.1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                acceptance.private_address(address)
        for address in ("10.0.2.2", "172.16.1.4", "192.168.1.20"):
            self.assertEqual(acceptance.private_address(address), address)
        self.assertEqual(acceptance.private_address("127.0.0.1", allow_loopback=True), "127.0.0.1")

    def test_synthetic_transport_sample_has_complete_raw_ip_record(self):
        data = acceptance.sample_pcap("127.0.0.1")
        self.assertEqual(acceptance.validate_pcap(data), 1)
        for malformed in (data[:-1], data[:24], b"not a pcap", data + b"\x00"):
            with self.assertRaises(AssertionError):
                acceptance.validate_pcap(malformed)

    def test_profile_restricts_tun_to_test_app_and_fixture_ip(self):
        profile = acceptance.profile("192.168.1.20")["template"]
        self.assertEqual(profile["inbounds"][0]["route_address"], ["192.168.1.20/32"])
        self.assertEqual(profile["inbounds"][0]["include_package"], ["io.sbeasy.android"])
        self.assertEqual(profile["route"]["final"], "direct")
        self.assertTrue(all(rule["type"] == "inline" for rule in profile["route"]["rule_set"]))
        self.assertTrue(all(rule["rules"] for rule in profile["route"]["rule_set"]))
        self.assertNotIn("http-debug-vpn", acceptance.DEFAULT_TESTS)

    def test_only_completed_expected_instrumentation_counts_as_native_pass(self):
        name = acceptance.CLASSES["capture"]
        report = (f"INSTRUMENTATION_STATUS: class={name}\n"
                  "INSTRUMENTATION_STATUS: test=tunPacketsAreFilteredSealedAndUploaded\n"
                  "INSTRUMENTATION_STATUS_CODE: 0\n"
                  "INSTRUMENTATION_CODE: -1\n")
        self.assertEqual(len(acceptance.instrumentation_results(report, [name])), 1)
        with self.assertRaises(acceptance.NotRun):
            acceptance.instrumentation_results(report, [name, acceptance.CLASSES["http-debug"]])
        with self.assertRaises(acceptance.NotRun):
            acceptance.instrumentation_results("OK (0 tests)\nINSTRUMENTATION_CODE: -1\n", [name])

    def test_assumption_skips_and_failures_cannot_be_reported_as_pass(self):
        name = acceptance.CLASSES["capture"]
        for code in (-3, -4):
            output = f"INSTRUMENTATION_STATUS_CODE: {code}\nOK (1 test)\nINSTRUMENTATION_CODE: -1\n"
            with self.assertRaises(acceptance.NotRun):
                acceptance.instrumentation_results(output, [name])
        for output in ("INSTRUMENTATION_STATUS_CODE: -2\nINSTRUMENTATION_CODE: -1\n",
                       "INSTRUMENTATION_FAILED: Process crashed", ""):
            with self.assertRaises(AssertionError):
                acceptance.instrumentation_results(output, [name])

    def test_mock_adb_preserves_enrollment_argument_and_requires_explicit_vpn_profile(self):
        # This checks command construction only. It does not count as Android
        # execution; real device acceptance remains a separate opt-in mode.
        versions = json.loads((acceptance.ROOT / "config/client-releases.json").read_text())["development"]["android"]
        for selected in ("capture", "all", "http-debug-vpn"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as temporary:
                calls, saved_profiles = [], []
                enrollment = "sbeasy://enroll?server=http%3A%2F%2F192.168.1.20%3A12345&code=one-use-code"
                fixture = SimpleNamespace(
                    public_address="192.168.1.20", output=Path(temporary),
                    http=SimpleNamespace(server_port=12346), udp=SimpleNamespace(server_address=("192.168.1.20", 12347)),
                    create_device=lambda *args: ({"id": "test-host"}, {"enrollment_uri": enrollment}),
                    redact=lambda value: value, verify_device_captures=lambda *args: [],
                    api=lambda path, body: saved_profiles.append(body) or {"id": "vpn-profile"})
                args = SimpleNamespace(adb="adb", device="fixture-serial", app_apk=None, test_apk=None,
                    plugin_apk=None, sandbox_probe_apk=None, tests=selected, timeout=300, keep_private_data=False)

                def invoke(command, **_kwargs):
                    calls.append(command)
                    tail = command[3:]
                    if tail == ["get-state"]:
                        output = "device\n"
                    elif tail == ["shell", "getprop ro.build.version.sdk"]:
                        output = "36\n"
                    elif tail == ["shell", "pm list instrumentation"]:
                        output = "instrumentation:" + acceptance.RUNNER + " (target=io.sbeasy.android)\n"
                    elif tail == ["shell", "dumpsys package " + acceptance.APP]:
                        output = f'versionName={versions["version"]}\nversionCode={versions["version_code"]} targetSdk=36\n'
                    elif tail[0] == "shell" and tail[1].startswith("pm path "):
                        output = "package:/fixture.apk\n"
                    elif tail[0] == "shell" and tail[1].startswith("am instrument "):
                        words = shlex.split(tail[1])
                        options = {words[index + 1]: words[index + 2] for index, word in enumerate(words) if word == "-e"}
                        self.assertEqual(options["captureEnrollment"], enrollment)
                        output = "".join(f"INSTRUMENTATION_STATUS: class={name}\nINSTRUMENTATION_STATUS: test=fixture\nINSTRUMENTATION_STATUS_CODE: 0\n"
                                         for name in options["class"].split(",")) + "INSTRUMENTATION_CODE: -1\n"
                    else:
                        output = ""
                    return subprocess.CompletedProcess(command, 0, output)

                with patch.object(acceptance.shutil, "which", return_value="/fixture/adb"), \
                     patch.object(acceptance.subprocess, "run", side_effect=invoke):
                    acceptance.run_device(args, fixture)
                self.assertEqual(len(saved_profiles), 1 if selected == "http-debug-vpn" else 0)
                if saved_profiles:
                    tun = saved_profiles[0]["template"]["inbounds"][0]
                    self.assertEqual(tun["route_address"], ["0.0.0.0/0"])
                    self.assertEqual(tun["include_package"], [acceptance.APP])
                shell_commands = [command[4] for command in calls if command[3] == "shell"]
                self.assertIn("am force-stop " + acceptance.APP, shell_commands)
                self.assertFalse(any("appops" in command or "pm clear" in command or " reverse " in command for command in shell_commands))


if __name__ == "__main__":
    unittest.main()
