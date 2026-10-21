"""Small helpers for isolated IP echo requests; metadata is strictly offline."""
from dataclasses import dataclass, field
import ipaddress
from typing import Mapping

MAX_RESPONSE_BYTES = 128 * 1024

@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)

class ResponseTooLarge(ValueError):
    pass

def public_ip(value: str) -> str:
    """Canonical public literal address; reject hostnames, scopes and URLs."""
    if not isinstance(value, str) or value != value.strip() or "%" in value:
        raise ValueError("Expected a public literal IP address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("Expected a public literal IP address") from None
    if (not address.is_global or address.is_multicast or address.is_reserved
            or address.is_unspecified or address.is_loopback or address.is_link_local):
        raise ValueError("Expected a public literal IP address")
    return str(address)
