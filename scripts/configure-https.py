#!/usr/bin/env python3
"""Create a private initial HTTPS deployment env file; never modify a live service."""
import argparse
import os
from pathlib import Path
import re
import secrets


def domain_name(value: str) -> str:
    value = value.lower().rstrip('.')
    if len(value) > 253 or '.' not in value or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
        for part in value.split('.')
    ) or all(part.isdigit() for part in value.split('.')):
        raise argparse.ArgumentTypeError('Use a DNS hostname without scheme, path or port')
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain', required=True, type=domain_name)
    parser.add_argument('--wireguard-hostname', type=domain_name)
    parser.add_argument('--output', type=Path, default=Path('.env'))
    args = parser.parse_args()
    content = (
        '# Generated initial deployment secrets; do not commit this file.\n'
        f'PANEL_DOMAIN={args.domain}\nPUBLIC_SERVER=https://{args.domain}\n'
        'BIND_ADDR=127.0.0.1:51821\n'
        f'JWT_SECRET={secrets.token_hex(32)}\nADMIN_PASSWORD={secrets.token_urlsafe(24)}\n'
        f'EXTERNAL_HOSTNAME={args.wireguard_hostname or args.domain}\n'
        f'CORS_ORIGINS=https://{args.domain}\n'
    )
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        parser.error(f'{args.output} already exists; preserve its keys and edit it explicitly')
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(content)
    print(f'Created {args.output} with private permissions. Read ADMIN_PASSWORD there for initial sign-in.')
    print(f'Point DNS to this server and allow TCP 80/443, then run docker compose up -d --build. Open https://{args.domain}.')


if __name__ == '__main__':
    main()
