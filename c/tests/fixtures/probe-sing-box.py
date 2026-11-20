#!/usr/bin/env python3
"""Offline sing-box CLI fixture for the platform latency route contracts."""
import json
import sys

if sys.argv[1:] != ["-c", "stdin", "tools", "--outbound", "probe", "fetch", "https://www.gstatic.com/generate_204"]:
    sys.exit(127)
config = json.load(sys.stdin)
outbound, = config["outbounds"]
if set(config) != {"outbounds"} or outbound["tag"] != "probe" or outbound["type"] == "direct":
    sys.exit(127)
if outbound["server"] == "t.example.com":
    sys.exit(1)
