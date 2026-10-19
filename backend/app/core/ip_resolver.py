"""
Trusted client-IP resolution (anti-spoofing).

Problem this solves
-------------------
``X-Forwarded-For`` is a CLIENT-CONTROLLED header. Anyone can send
``X-Forwarded-For: 1.2.3.4`` and the previous code happily used the
leftmost entry as "the" client IP — so an attacker could:

  * pollute IP history / abuse counters with fake IPs,
  * evade IP-based rate limits and blocks by rotating the header,
  * make forensic logs disagree with what the defense layer actually
    blocked on (the middleware uses the real socket peer).

Policy
------
* If the direct TCP peer is inside ``TRUSTED_PROXY_CIDRS`` (a proxy we
  control — e.g. a CDN edge), we read the X-Forwarded-For chain from
  RIGHT to LEFT (rightmost = added by the closest hop, least
  client-influenceable), skip trusted hops, and return the first
  untrusted, well-formed IP.
* Otherwise we return the direct socket peer and IGNORE X-Forwarded-For
  entirely (the spoof-proof default).
* With ``TRUSTED_PROXY_CIDRS`` empty (the default), the socket peer is
  always used — behaviour is strictly safer than before in every
  deployment, and behind a real proxy you add the proxy CIDRs once in
  .env and everyone resolves correctly (one shared proxy IP no longer
  means "one shared rate-limit bucket for the whole planet").

Every hop is validated with ``ipaddress``; malformed hops are dropped,
never raised.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from app.core.config import settings


@lru_cache(maxsize=1)
def _trusted_networks() -> tuple:
    raw = (settings.TRUSTED_PROXY_CIDRS or "").strip()
    if not raw:
        return ()
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def is_trusted_proxy(ip: str) -> bool:
    """True if *ip* is one of our own proxies (trusted to set XFF)."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in _trusted_networks())


def parse_xff_chain(header_value: str) -> list[str]:
    """Split an XFF header into well-formed IPs, left-to-right."""
    out: list[str] = []
    for part in (header_value or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ipaddress.ip_address(part)
        except ValueError:
            continue  # drop malformed/spoofed garbage
        out.append(part)
    return out


def resolve_client_ip(direct_peer: str | None, request_headers) -> str:
    """
    Resolve the real client IP from a request.

    Parameters
    ----------
    direct_peer:
        The TCP peer address (``request.client.host``).
    request_headers:
        The request headers (anything with ``.get("x-forwarded-for")``).

    Returns
    -------
    str
        The resolved client IP, or ``"unknown"`` if nothing usable.
    """
    peer = (direct_peer or "").strip()
    if not peer or not is_trusted_proxy(peer):
        # Never trust XFF from an untrusted peer.
        return peer or "unknown"

    chain = parse_xff_chain(request_headers.get("x-forwarded-for", ""))
    if not chain:
        return peer

    # Right-to-left: skip our own proxies, keep the first untrusted hop.
    for candidate in reversed(chain):
        if not is_trusted_proxy(candidate):
            return candidate
    # Every hop was one of our proxies — use the leftmost (original client).
    return chain[0]
