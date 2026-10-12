"""Windows private, length-prefixed stdin/stdout worker. No public control API."""
import json
import os
import struct
import sys

if sys.platform == "win32":
    import msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

reader, writer = sys.stdin.buffer, sys.stdout.buffer
# mitmproxy and imported libraries must never print into the framed channel.
sys.stdout = sys.stderr = open(os.devnull, "w")
from engine import dispatch


def read_exact(length):
    result = bytearray()
    while len(result) < length:
        part = reader.read(length - len(result))
        if not part:
            raise EOFError
        result.extend(part)
    return result


def main():
    while True:
        try:
            length, = struct.unpack("<I", read_exact(4))
            if not 0 < length <= 2 * 1024 * 1024:
                break
            request = json.loads(read_exact(length))
            try:
                response = dict(ok=True, result=dispatch(request["method"], request.get("params", {})))
            except Exception as error:
                response = dict(ok=False, code="HTTP_DEBUG_ERROR", message=str(error)[:500])
            content = json.dumps(response).encode()
            writer.write(struct.pack("<I", len(content)) + content)
            writer.flush()
        except EOFError:
            break


if __name__ == "__main__":
    main()
