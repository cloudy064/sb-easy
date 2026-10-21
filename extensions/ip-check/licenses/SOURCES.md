# Runtime notices

The optional worker is frozen from Python 3.13.12. It uses Python's standard
library and its bundled native dependencies, including OpenSSL 3.5.5 and libffi.
No mitmproxy runtime is imported or included.

- `Python-Third-Party.rst`: CPython v3.13.12 documentation, including the Python
  and bundled third-party licenses (libffi, OpenSSL, zlib and others).
  Source: https://github.com/python/cpython/blob/v3.13.12/Doc/license.rst
- `OpenSSL.txt`: OpenSSL 3.5.5 Apache 2.0 license.
  Source: https://github.com/openssl/openssl/blob/openssl-3.5.5/LICENSE.txt

The packager additionally includes the build interpreter's `LICENSE.txt` and
PyInstaller's distribution notices, including its bootloader exception.
