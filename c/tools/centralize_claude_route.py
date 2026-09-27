#!/usr/bin/env python3
"""Plan/apply one fixed Claude egress across central profiles, with rollback.

Credentials: SB_EASY_ADMIN_TOKEN, or SB_EASY_ADMIN_PASSWORD (username defaults
to admin). Backups contain proxy credentials and are created with mode 0600.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import urllib.request

DOMAINS = ["anyrouter.top", "anthropic.com", "claude.ai", "claude.com",
           "datadoghq.com", "sentry.io", "githubusercontent.com"]
FIELDS = ("name", "template", "mode", "rule_script", "rule_script_enabled")


class API:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.token = os.environ.get("SB_EASY_ADMIN_TOKEN", "")
        if not self.token:
            self.token = self.call("/api/auth/login", {
                "username": os.environ.get("SB_EASY_ADMIN_USERNAME", "admin"),
                "password": os.environ["SB_EASY_ADMIN_PASSWORD"]})["token"]

    def call(self, path, body=None, method=None):
        headers = {"Authorization": "Bearer " + self.token}
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        with self.opener.open(req, timeout=30) as response:
            return json.load(response)


def plan(api, suffix):
    profiles = api.call("/api/hosts/profiles")
    hosts = api.call("/api/hosts")
    nodes = api.call("/api/proxy/nodes")
    if isinstance(nodes, dict):
        nodes = nodes["nodes"]
    changes = []
    for profile in profiles:
        original = {key: profile[key] for key in FIELDS if key in profile}
        if isinstance(original["template"], str):
            original["template"] = json.loads(original["template"])
        desired = copy.deepcopy(original)
        candidates = desired["template"].get("outbounds", []) if desired["mode"] == "full" else nodes
        matches = [node for node in candidates if node.get("tag", "").endswith(suffix)
                   and node.get("enabled", True) and node.get("type", node.get("node_type")) not in ("selector", "urltest")]
        if len(matches) != 1:
            raise ValueError(f"profile {profile['id']}: expected one fixed node ending in {suffix}, got {len(matches)}")
        tag = matches[0]["tag"]
        # Verify each assigned host actually renders the selected outbound.
        for host in hosts:
            if (host.get("profile_id") or "default") != profile["id"]:
                continue
            config = api.call(f"/api/hosts/{host['id']}/config")
            if not any(node.get("tag") == tag for node in config.get("outbounds", [])):
                raise ValueError(f"host {host['id']} does not have outbound {tag}")
        rules = desired["template"].setdefault("route", {}).setdefault("rules", [])
        # Replace only our exact domain set; preserve every unrelated rule.
        rules[:] = [rule for rule in rules if set(rule.get("domain_suffix", [])) != set(DOMAINS)]
        index = 0
        while index < len(rules) and rules[index].get("action") in ("sniff", "resolve", "hijack-dns"):
            index += 1
        rules.insert(index, {"domain_suffix": DOMAINS, "outbound": tag})
        if desired.get("rule_script_enabled"):
            assigned = [host for host in hosts if (host.get("profile_id") or "default") == profile["id"]]
            for host in assigned or [{"id": "preflight", "name": "preflight", "capabilities": {}}]:
                checked = api.call("/api/hosts/rule-script/test", {
                    "rule_script": desired["rule_script"], "context": {
                        "host": host, "outboundTags": [node["tag"] for node in candidates],
                        "currentRules": rules}})
                if {"domain_suffix": DOMAINS, "outbound": tag} not in checked["rules"]:
                    raise ValueError(f"profile {profile['id']} rule script removes the fixed egress rule")
        if original != desired:
            changes.append({"id": profile["id"], "name": profile["name"], "outbound": tag,
                            "before": original, "after": desired})
    return changes


def apply(api, changes, backup):
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        json.dump(changes, file, ensure_ascii=False, indent=2)
        file.flush()
        os.fsync(file.fileno())
    updated = []
    try:
        for change in changes:
            # Include the in-flight write: a timeout can occur after it commits.
            updated.append(change)
            api.call("/api/hosts/profiles/" + change["id"], change["after"], "PUT")
    except Exception:
        for change in reversed(updated):
            api.call("/api/hosts/profiles/" + change["id"], change["before"], "PUT")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    parser.add_argument("--node-suffix", default="🇯🇵 日本Z03 | IEPL")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--rollback", type=Path)
    args = parser.parse_args()
    api = API(args.server)
    if args.rollback:
        for change in reversed(json.loads(args.rollback.read_text())):
            api.call("/api/hosts/profiles/" + change["id"], change["before"], "PUT")
        print("restored central profiles")
        return
    changes = plan(api, args.node_suffix)
    for change in changes:
        print(f"{change['name']}: Claude domains -> {change['outbound']}")
    print(f"{len(changes)} profiles; domains: {', '.join(DOMAINS)}")
    if args.apply:
        if not args.backup:
            parser.error("--apply requires --backup")
        apply(api, changes, args.backup)
        assert not plan(api, args.node_suffix), "post-write verification failed"
        print("central profile updates verified; agents will receive them on their next poll")


if __name__ == "__main__":
    main()
