#!/usr/bin/env python3
"""Prepare the reviewed UDP shutdown fix without modifying the module cache.

Run from the pinned sing-box source directory. --output receipt.json creates
receipt.mod and receipt.sum; use go -modfile receipt.mod. Go forbids filesystem
overlays under GOMODCACHE, so a private dependency copy is used instead.
An upstream dependency change requires an explicit review.
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess

MODULE = "github.com/sagernet/sing"
VERSION = "v0.9.7-0.20260929150544-0ad23b637bd4"
SOURCE_HASH = "e9f1e7f9fdc0d58f85ecd636bf1fa43b1214ba84c4f0123e5ead4c02f5e1d310"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    subprocess.run(["go", "mod", "download", MODULE], check=True)
    module = json.loads(subprocess.check_output(["go", "list", "-m", "-json", MODULE]))
    if module["Version"] != VERSION or module.get("Replace"):
        raise SystemExit("Unreviewed sing dependency; UDP overlay refused")
    source = pathlib.Path(module["Dir"]) / "common/udpnat/service.go"
    original = source.read_bytes()
    if hashlib.sha256(original).hexdigest() != SOURCE_HASH:
        raise SystemExit("UDP source digest changed; overlay refused")
    old = "\tc.data <- packet{\n\t\tdata:        buffer,\n\t\tdestination: destination,\n\t}\n"
    new = """\t// sb-easy: a revoked flow must not strand the listener on a full
\t// packet queue. UDP backpressure drops a whole datagram.
\tselect {
\tcase c.data <- packet{data: buffer, destination: destination}:
\tcase <-c.ctx.Done():
\t\tbuffer.Release()
\tdefault:
\t\tbuffer.Release()
\t}
"""
    text = original.decode()
    if text.count(old) != 1:
        raise SystemExit("UDP enqueue patch anchor changed")
    text = text.replace(old, new)
    old = "\t\t\ts.NewContextPacketEx(ctx, key, buffer, source, destination, init)\n\t\t}\n"
    new = "\t\t\ts.NewContextPacketEx(ctx, key, buffer, source, destination, init)\n\t\t} else {\n\t\t\tbuffer.Release()\n\t\t}\n"
    if text.count(old) != 1:
        raise SystemExit("UDP canceled-input patch anchor changed")
    text = text.replace(old, new)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    dependency = output.with_suffix(".sing")
    marker = dependency / ".sb-easy-private-copy"
    identity = MODULE + "@" + VERSION + "\n"
    if dependency.exists():
        if not marker.is_file() or marker.read_text() != identity:
            raise SystemExit("Refusing to replace an unrelated dependency directory")
        # Module-cache modes are read-only; only make our own copy writable.
        for path in dependency.rglob("*"):
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() else 0o644)
        dependency.chmod(0o755)
        shutil.rmtree(dependency)
    shutil.copytree(module["Dir"], dependency)
    dependency.chmod(0o755)
    marker.write_text(identity)
    patched = dependency / "common/udpnat/service.go"
    patched.chmod(0o644)
    patched.write_text(text)
    modfile = output.with_suffix(".mod")
    shutil.copyfile("go.mod", modfile)
    shutil.copyfile("go.sum", output.with_suffix(".sum"))
    subprocess.run(["go", "mod", "edit", "-modfile", str(modfile),
                    "-replace", MODULE + "=" + str(dependency)], check=True)
    output.write_text(json.dumps({
        "schema": 1, "module": MODULE, "version": VERSION,
        "source_sha256": SOURCE_HASH,
        "patched_sha256": hashlib.sha256(patched.read_bytes()).hexdigest(),
        "modfile": str(modfile), "dependency": str(dependency)
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
