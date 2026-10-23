#!/usr/bin/env python3
"""Validate/sign plugin catalogs with an external RSA key. Python stdlib + OpenSSL."""
import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit, unquote

MAX_ENVELOPE = 1024 * 1024
MAX_PAYLOAD = 512 * 1024
IDENTIFIER = re.compile(r'[a-zA-Z0-9_-]{1,64}\Z')
VERSION = re.compile(r'(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
PLATFORMS = {'android', 'windows', 'linux', 'macos'}
RELEASE_FIELDS = {'id', 'platform', 'version', 'build', 'abi', 'api', 'min_host', 'max_host',
                  'min_core', 'max_core', 'min_os', 'url', 'sha256', 'bytes', 'package', 'signer_sha256', 'permissions'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_json(data, limit):
    require(0 < len(data) <= limit, 'JSON size limit exceeded or input empty')
    def pairs(rows):
        result = {}
        for name, value in rows:
            require(name not in result, 'Duplicate JSON key')
            result[name] = value
        return result
    def constant(_):
        raise ValueError('Non-finite JSON number')
    return json.loads(data.decode('utf-8', errors='strict'), object_pairs_hook=pairs, parse_constant=constant)


def keys(obj, expected):
    require(type(obj) is dict and set(obj) == expected, 'Unknown or missing object fields')


def integer(value, minimum, maximum):
    require(type(value) is int and minimum <= value <= maximum, 'Integer outside supported range')


def identifier(value):
    require(type(value) is str and IDENTIFIER.fullmatch(value), 'Invalid identifier')


def version(value):
    require(type(value) is str and VERSION.fullmatch(value), 'Expected a three-component version')
    return tuple(map(int, value.split('.')))


def canonical64(value):
    require(type(value) is str, 'Base64 value must be a string')
    try:
        result = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError('Invalid Base64') from error
    require(base64.b64encode(result).decode('ascii') == value, 'Noncanonical Base64')
    return result


def validate_payload(value, now=None, require_fresh=True):
    keys(value, {'sequence', 'issued_at', 'expires_at', 'releases', 'revocations'})
    integer(value['sequence'], 1, 9007199254740991)
    integer(value['issued_at'], 1, 4102444800)
    integer(value['expires_at'], 1, 4102444800)
    require(0 < value['expires_at'] - value['issued_at'] <= 90 * 86400, 'Catalog validity must be 1 second to 90 days')
    if require_fresh:
        now = int(time.time()) if now is None else now
        require(value['issued_at'] <= now + 300 and value['expires_at'] > now, 'Catalog is expired or not yet valid')
    require(type(value['releases']) is list and len(value['releases']) <= 128, 'Too many releases')
    require(type(value['revocations']) is list and len(value['revocations']) <= 256, 'Too many revocations')
    seen = set()
    for release in value['releases']:
        keys(release, RELEASE_FIELDS)
        identifier(release['id']); identifier(release['abi'])
        require(release['platform'] in PLATFORMS, 'Unsupported platform')
        version(release['version'])
        integer(release['build'], 1, 2100000000); integer(release['api'], 1, 65535)
        integer(release['min_os'], 0, 999999)
        require(version(release['min_host']) < version(release['max_host']), 'Empty host version range')
        require(version(release['min_core']) < version(release['max_core']), 'Empty core version range')
        require(type(release['url']) is str and len(release['url']) <= 4096 and not any(c.isspace() or ord(c) < 32 for c in release['url']), 'Invalid URL')
        url = urlsplit(release['url'])
        require(url.scheme == 'https' and url.hostname and url.username is None and url.password is None and '#' not in release['url'], 'Artifacts require credential-free HTTPS URLs')
        if url.port is not None: integer(url.port, 1, 65535)
        require(type(release['sha256']) is str and SHA256.fullmatch(release['sha256']), 'Invalid artifact SHA-256')
        integer(release['bytes'], 1, 160 * 1024 * 1024)
        if release['platform'] == 'android':
            require(type(release['package']) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+', release['package']), 'Invalid Android package')
            require(type(release['signer_sha256']) is str and SHA256.fullmatch(release['signer_sha256']), 'Invalid Android signer digest')
        else:
            require(release['package'] == '' and release['signer_sha256'] == '', 'Package/signer fields are Android-only')
        permissions = release['permissions']
        require(type(permissions) is list and len(permissions) <= 16, 'Too many capabilities')
        for permission in permissions: identifier(permission)
        require(len(set(permissions)) == len(permissions), 'Duplicate capability')
        identity = (release['platform'], release['id'], release['abi'], release['build'])
        require(identity not in seen, 'Duplicate release')
        seen.add(identity)
    seen = set()
    for revoked in value['revocations']:
        keys(revoked, {'id', 'platform', 'build', 'reason'})
        identifier(revoked['id']); require(revoked['platform'] in PLATFORMS, 'Unsupported platform')
        integer(revoked['build'], 1, 2100000000)
        reason = revoked['reason']
        require(type(reason) is str and 1 <= len(reason) <= 240 and not any(ord(c) < 32 or ord(c) == 127 for c in reason), 'Invalid revocation reason')
        identity = (revoked['platform'], revoked['id'], revoked['build'])
        require(identity not in seen, 'Duplicate revocation')
        seen.add(identity)
    return value


def openssl(arguments, data=None):
    result = subprocess.run(['openssl', *arguments], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(result.returncode == 0, 'OpenSSL operation failed; verify the key, algorithm and signature')
    return result.stdout


def trust_keys(data, format_name="sb-easy.plugin-catalog.keys"):
    root = strict_json(data, 64 * 1024)
    keys(root, {'format', 'version', 'keys'})
    require(root['format'] == format_name and type(root['version']) is int and root['version'] == 1, 'Unsupported trust file')
    require(type(root['keys']) is dict and len(root['keys']) <= 16, 'Invalid trust allowlist')
    result = {}
    for key_id, encoded in root['keys'].items():
        identifier(key_id)
        der = canonical64(encoded)
        require(1 <= len(der) <= 1024, 'Invalid public-key size')
        with tempfile.TemporaryDirectory(prefix='sb-plugin-pubkey-') as temp:
            path = Path(temp) / 'key.der'; path.write_bytes(der)
            details = openssl(['pkey', '-pubin', '-inform', 'DER', '-in', str(path), '-text_pub', '-noout']).decode('ascii')
            match = re.search(r'Public-Key: \((\d+) bit\)', details)
            require(match and 2048 <= int(match.group(1)) <= 4096 and 'Modulus:' in details, 'Trust keys must be RSA 2048–4096')
            result[key_id] = openssl(['pkey', '-pubin', '-inform', 'DER', '-in', str(path), '-outform', 'PEM'])
    return result


def verify(envelope_data, allowlist, now=None, require_fresh=True, *, format_name="sb-easy.plugin-catalog", prefix=b"", validator=validate_payload):
    envelope = strict_json(envelope_data, MAX_ENVELOPE)
    keys(envelope, {'format', 'version', 'algorithm', 'key_id', 'payload', 'signature'})
    require(envelope['format'] == format_name and type(envelope['version']) is int and envelope['version'] == 1 and envelope['algorithm'] == 'rsa-pss-sha256', 'Unsupported catalog envelope')
    identifier(envelope['key_id'])
    require(envelope['key_id'] in allowlist, 'Catalog key is not trusted by this build')
    payload = canonical64(envelope['payload']); signature = canonical64(envelope['signature'])
    require(0 < len(payload) <= MAX_PAYLOAD and 256 <= len(signature) <= 512, 'Invalid signed payload/signature size')
    with tempfile.TemporaryDirectory(prefix='sb-plugin-verify-') as temp:
        public = Path(temp) / 'public.pem'; public.write_bytes(allowlist[envelope['key_id']])
        sig = Path(temp) / 'signature.bin'; sig.write_bytes(signature)
        openssl(['dgst', '-sha256', '-verify', str(public), '-signature', str(sig),
                 '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:32', '-sigopt', 'rsa_mgf1_md:sha256'], prefix + payload)
    parsed = validator(strict_json(payload, MAX_PAYLOAD), now, require_fresh)
    return parsed, hashlib.sha256(payload).hexdigest()


def sign(payload_data, private_key, key_id, allowlist, now=None, artifact_root=None, *, format_name="sb-easy.plugin-catalog", prefix=b"", validator=validate_payload):
    payload = validator(strict_json(payload_data, MAX_PAYLOAD), now)
    identifier(key_id); require(key_id in allowlist, 'Signing key ID must already be in the host trust file')
    if artifact_root is not None:
        folder = Path(artifact_root).resolve()
        for release in payload['releases']:
            name = unquote(urlsplit(release['url']).path.rsplit('/', 1)[-1])
            require(name and '/' not in name and '\\' not in name and name not in ('.', '..'), 'Artifact URL has no safe filename')
            path = folder / name
            require(path.is_file() and path.stat().st_size == release['bytes'], 'Local artifact missing or wrong size')
            with path.open('rb') as artifact:
                require(hashlib.file_digest(artifact, 'sha256').hexdigest() == release['sha256'], 'Local artifact digest mismatch')
    # Keep the exact supplied bytes. Reordering/normalizing signed JSON is forbidden.
    signature = openssl(['dgst', '-sha256', '-sign', str(private_key), '-sigopt', 'rsa_padding_mode:pss',
                         '-sigopt', 'rsa_pss_saltlen:32', '-sigopt', 'rsa_mgf1_md:sha256'], prefix + payload_data)
    envelope = {'format': format_name, 'version': 1, 'algorithm': 'rsa-pss-sha256', 'key_id': key_id,
                'payload': base64.b64encode(payload_data).decode('ascii'), 'signature': base64.b64encode(signature).decode('ascii')}
    encoded = json.dumps(envelope, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    verify(encoded, allowlist, now, format_name=format_name, prefix=prefix, validator=validator)
    return encoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    signer = commands.add_parser('sign')
    signer.add_argument('--payload', type=Path, required=True); signer.add_argument('--private-key', type=Path, required=True)
    signer.add_argument('--key-id', required=True); signer.add_argument('--output', type=Path, required=True)
    signer.add_argument('--artifact-root', type=Path)
    verifier = commands.add_parser('verify'); verifier.add_argument('--catalog', type=Path, required=True)
    trust = commands.add_parser('trust', help='Prepare a host trust config from an external public PEM (never a private key)')
    trust.add_argument('--public-key', type=Path, required=True); trust.add_argument('--key-id', required=True)
    trust.add_argument('--output', type=Path, required=True)
    for command in (signer, verifier):
        command.add_argument('--keys', type=Path, required=True); command.add_argument('--now', type=int)
    args = parser.parse_args()
    if args.command == 'trust':
        identifier(args.key_id)
        der = openssl(['pkey', '-pubin', '-in', str(args.public_key), '-outform', 'DER'])
        encoded = json.dumps({'format': 'sb-easy.plugin-catalog.keys', 'version': 1,
                              'keys': {args.key_id: base64.b64encode(der).decode('ascii')}}, indent=2).encode('utf-8')
        trust_keys(encoded)
        args.output.write_bytes(encoded + b'\n')
        print(f'Public trust config written: {args.output}; key SHA-256 {hashlib.sha256(der).hexdigest()}')
        return
    allowlist = trust_keys(args.keys.read_bytes())
    if args.command == 'sign':
        encoded = sign(args.payload.read_bytes(), args.private_key, args.key_id, allowlist, args.now, args.artifact_root)
        args.output.write_bytes(encoded + b'\n')
        print(f'Signed catalog written: {args.output}')
    else:
        payload, digest = verify(args.catalog.read_bytes(), allowlist, args.now)
        print(json.dumps({'sequence': payload['sequence'], 'payload_sha256': digest, 'releases': len(payload['releases']), 'revocations': len(payload['revocations'])}))


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f'Catalog rejected: {error}', file=sys.stderr); sys.exit(2)
