#!/usr/bin/env python3
"""Validate build identities and the reviewed published-download inventory.

This inventory is for the download page, not an updater trust root. Native
updates still require their independently signed catalogs/release manifests.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/cloudy064/sb-easy"


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+\.\d+", value):
        raise ValueError("Application versions must be major.minor.patch")
    return tuple(map(int, value.split(".")))


def validate(data):
    if data.get("schema_version") != 1 or data.get("repository") != REPOSITORY:
        raise ValueError("Unsupported client manifest")
    development = data["development"]
    if set(development) != {"android", "windows", "linux", "apple", "service"}:
        raise ValueError("Missing application build identity")
    for entry in development.values():
        version(entry["version"])
    for platform, field in (("android", "version_code"), ("apple", "build")):
        value = development[platform][field]
        if type(value) is not int or not 0 < value < 2147483647:
            raise ValueError("Invalid native build number")
    if any(a > b for a, b in zip(version(development["windows"]["version"]), (255, 255, 65535))):
        raise ValueError("Windows version exceeds MSI limits")
    for platform, release in data["published"].items():
        if platform not in {"android", "windows", "linux", "apple"}:
            raise ValueError("Unknown published client platform")
        if version(release["version"]) > version(development[platform]["version"]):
            raise ValueError("Source version cannot precede its published release")
        version(release["core_version"])
        if release["channel"] not in {"test-signed", "unsigned-preview", "stable"}:
            raise ValueError("Unknown publication channel")
        if platform == "android":
            same_version = release["version"] == development[platform]["version"]
            release_code = release["version_code"]
            source_code = development[platform]["version_code"]
            if type(release_code) is not int or release_code <= 0 or (same_version and release_code != source_code) or (not same_version and release_code >= source_code):
                raise ValueError("Android versionCode must match its published version or advance for a newer source version")
        features = release.get("features", {})
        if type(features) is not dict or any(key not in {"packet_capture", "http_debug"} or type(value) is not bool for key, value in features.items()):
            raise ValueError("Invalid published feature declarations")
        tag = release["tag"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", tag) or release["release_url"] != REPOSITORY + "/releases/tag/" + tag:
            raise ValueError("Published release URL is not bound to its tag")
        prefix = REPOSITORY + "/releases/download/" + tag + "/"
        for field in ("source_url", "checksums_url"):
            value = release[field]
            if not value.startswith(prefix) or not re.fullmatch(r"[A-Za-z0-9_.-]+", value[len(prefix):]):
                raise ValueError("Published source/checksum URL is outside its release")
        artifacts = release["artifacts"]
        names = set()
        for artifact in artifacts:
            name = artifact["name"]
            if name in names or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                raise ValueError("Invalid or duplicate artifact name")
            names.add(name)
            if artifact["url"] != prefix + name or release["version"] not in name:
                raise ValueError("Artifact URL/version does not match its release")
            if not re.fullmatch(r"[a-f0-9]{64}", artifact["sha256"]) or type(artifact["size"]) is not int or artifact["size"] <= 0:
                raise ValueError("Artifact needs its exact SHA-256 and byte length")
            if artifact["format"] not in {"apk", "msi", "zip", "deb", "dmg", "ipa"} or not name.endswith("." + artifact["format"]):
                raise ValueError("Artifact format mismatch")
        if not artifacts:
            raise ValueError("Published platforms need real downloadable artifacts")
        if platform == "android" and {a["architecture"] for a in artifacts} != {"arm64-v8a", "armeabi-v7a", "x86", "x86_64", "universal"}:
            raise ValueError("Android download inventory is incomplete")
        if platform == "windows" and {(a["architecture"], a["format"]) for a in artifacts} != {("x64", "msi"), ("x64", "zip")}:
            raise ValueError("Windows download inventory is incomplete")


def compare_published(expected, actual):
    if actual.get("draft") or actual.get("tag_name") != expected["tag"] or actual.get("html_url") != expected["release_url"]:
        raise ValueError("Release is missing, private, or points at another tag")
    assets = {a["name"]: a for a in actual["assets"]}
    for artifact in expected["artifacts"]:
        remote = assets.get(artifact["name"], {})
        if remote.get("state") != "uploaded" or remote.get("size") != artifact["size"] or remote.get("digest") != "sha256:" + artifact["sha256"] or remote.get("browser_download_url") != artifact["url"]:
            raise ValueError("Published artifact metadata changed: " + artifact["name"])
    urls = {a["browser_download_url"] for a in actual["assets"] if a.get("state") == "uploaded"}
    if expected["source_url"] not in urls or expected["checksums_url"] not in urls:
        raise ValueError("Published source or checksums are missing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    get = sub.add_parser("get"); get.add_argument("key")
    sub.add_parser("verify-published")
    artifact = sub.add_parser("verify-artifact"); artifact.add_argument("platform"); artifact.add_argument("file", type=Path)
    args = parser.parse_args()
    data = json.loads((ROOT / "config/client-releases.json").read_text())
    validate(data)
    if args.command == "get":
        value = data
        for key in args.key.split("."):
            value = value[key]
        print(value if isinstance(value, (str, int)) else json.dumps(value))
    elif args.command == "verify-published":
        for release in data["published"].values():
            url = "https://api.github.com/repos/cloudy064/sb-easy/releases/tags/" + release["tag"]
            request = urllib.request.Request(url, headers={"User-Agent": "sb-easy-release-check", "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("Release metadata exceeds the limit")
            compare_published(release, json.loads(raw))
        print("Published download tags, sizes, SHA-256 digests, source and checksums match")
    elif args.command == "verify-artifact":
        expected = next(a for a in data["published"][args.platform]["artifacts"] if a["name"] == args.file.name)
        with args.file.open("rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        if args.file.stat().st_size != expected["size"] or digest != expected["sha256"]:
            raise ValueError("Downloaded artifact does not match the reviewed published inventory")
        print("Verified " + args.file.name)
    else:
        apple = json.loads((ROOT / "apple/project.yml").read_text())["settings"]["base"]
        if apple["MARKETING_VERSION"] != data["development"]["apple"]["version"] or int(apple["CURRENT_PROJECT_VERSION"]) != data["development"]["apple"]["build"]:
            raise ValueError("Apple project identity differs from the client manifest")
        print("Client build identities and published download inventory are valid")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, StopIteration) as error:
        sys.exit(str(error) or "Artifact is not in the published inventory")
