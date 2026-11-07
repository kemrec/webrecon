"""Expand a target specification into individual hosts.

servicescan accepts more than a single IP. A spec is one or more tokens
(given on the command line, and/or one-per-line via ``-iL FILE``). Each token
may be:

  - a single IPv4/IPv6 address        ``10.0.0.5``   ``2001:db8::1``
  - a hostname                        ``app.lab.internal``
  - a CIDR block                      ``10.0.0.0/24``  ``2001:db8::/120``
  - an nmap-style octet range         ``10.0.0.1-50``  ``10.0.0-2.1-254``

When nmap runs it is handed the raw tokens and expands them itself, so this
module is used for the no-nmap fallback path (and for ``-iL`` file reading).
IPv6 CIDR and hostnames pass through unexpanded; hostnames are resolved later.
"""
from __future__ import annotations

import ipaddress

# Safety cap so a stray /8 or wildcard spec cannot blow up memory.
DEFAULT_CAP = 65536


def read_target_file(path: str) -> list[str]:
    """Read a target list file (one token per line, '#' comments allowed)."""
    out: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                out.extend(line.replace(",", " ").split())
    return out


def _is_ipv4ish(token: str) -> bool:
    core = token.split("/", 1)[0]
    parts = core.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        seg = p.split("-", 1)
        for s in seg:
            if not s.isdigit():
                return False
    return True


def _expand_cidr(token: str, cap: int) -> list[str]:
    net = ipaddress.ip_network(token, strict=False)
    # /31 and /32 (and v6 equivalents) have no "hosts"; use the addresses.
    if net.num_addresses <= 2:
        it = net
    else:
        it = net.hosts()
    out: list[str] = []
    for addr in it:
        out.append(str(addr))
        if len(out) >= cap:
            break
    return out


def _expand_ipv4_range(token: str, cap: int) -> list[str]:
    """Expand an nmap-style IPv4 octet range, e.g. 10.0.0-2.1-254."""
    octet_sets: list[list[int]] = []
    for part in token.split("."):
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
        else:
            lo = hi = int(part)
        if not (0 <= lo <= hi <= 255):
            raise ValueError(f"bad octet range: {part}")
        octet_sets.append(list(range(lo, hi + 1)))

    out: list[str] = []
    for a in octet_sets[0]:
        for b in octet_sets[1]:
            for c in octet_sets[2]:
                for d in octet_sets[3]:
                    out.append(f"{a}.{b}.{c}.{d}")
                    if len(out) >= cap:
                        return out
    return out


def expand_token(token: str, cap: int = DEFAULT_CAP) -> list[str]:
    """Expand one token into concrete hosts (hostnames pass through)."""
    token = token.strip()
    if not token:
        return []

    # CIDR (v4 or v6)
    if "/" in token:
        try:
            return _expand_cidr(token, cap)
        except ValueError:
            return [token]

    # IPv4 single or octet range
    if _is_ipv4ish(token):
        if "-" in token:
            try:
                return _expand_ipv4_range(token, cap)
            except ValueError:
                return [token]
        return [token]

    # hostname or IPv6 literal: leave as-is
    return [token]


def expand(tokens: list[str], cap: int = DEFAULT_CAP) -> list[str]:
    """Expand many tokens, de-duplicated, order-preserving, capped."""
    seen: set[str] = set()
    out: list[str] = []
    for tok in tokens:
        for h in expand_token(tok, cap):
            if h not in seen:
                seen.add(h)
                out.append(h)
                if len(out) >= cap:
                    return out
    return out
