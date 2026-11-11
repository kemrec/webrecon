"""Shared helpers: logging, URL normalization, scope checks."""
from __future__ import annotations

import sys
import re
from urllib.parse import urlparse, urljoin, urldefrag, parse_qsl, urlencode, urlunparse


# ---- tiny colored logger (no external deps) ----
class C:
    R = "\033[0m"; B = "\033[1m"
    RED = "\033[31m"; GRN = "\033[32m"; YEL = "\033[33m"
    BLU = "\033[34m"; MAG = "\033[35m"; CYN = "\033[36m"; GRY = "\033[90m"


_QUIET = False
_VERBOSE = False


def set_log_levels(quiet: bool, verbose: bool) -> None:
    global _QUIET, _VERBOSE
    _QUIET, _VERBOSE = quiet, verbose


def _emit(prefix: str, color: str, msg: str) -> None:
    if _QUIET:
        return
    sys.stderr.write(f"{color}{prefix}{C.R} {msg}\n")
    sys.stderr.flush()


def info(msg: str) -> None:   _emit("[*]", C.CYN, msg)
def good(msg: str) -> None:   _emit("[+]", C.GRN, msg)
def warn(msg: str) -> None:   _emit("[!]", C.YEL, msg)
def err(msg: str) -> None:    _emit("[x]", C.RED, msg)
def hit(msg: str) -> None:    _emit("[>]", C.MAG, msg)


def debug(msg: str) -> None:
    if _VERBOSE and not _QUIET:
        _emit("[d]", C.GRY, msg)


# ---- URL helpers ----
def normalize_url(base: str, link: str) -> str | None:
    """Resolve link against base, drop fragments, return absolute http(s) URL or None."""
    if not link:
        return None
    link = link.strip()
    low = link.lower()
    if low.startswith(("javascript:", "mailto:", "tel:", "data:", "blob:", "#")):
        return None
    try:
        absolute = urljoin(base, link)
        absolute, _ = urldefrag(absolute)
        p = urlparse(absolute)
        if p.scheme not in ("http", "https"):
            return None
        if not p.netloc:
            return None
        return absolute
    except Exception:
        return None


def ensure_scheme(target: str) -> str:
    if "://" not in target:
        return "https://" + target
    return target


def host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split("@")[-1].split(":")[0].lower()
    except Exception:
        return ""


def hostport_of(url: str) -> tuple[str, int | None]:
    """Return (host, explicit_port_or_None) for a URL."""
    try:
        p = urlparse(ensure_scheme(url))
        return (p.hostname or "").lower(), p.port
    except Exception:
        return "", None


def with_port(host: str, port: int | None) -> str:
    """host[:port] — port appended only when given (non-default caller choice).
    An IPv6 literal is wrapped in brackets so `addr:port` stays unambiguous."""
    if host and ":" in host and not host.startswith("["):
        host = f"[{host}]"   # IPv6 literal
    return f"{host}:{port}" if port else host


def is_ip(host: str) -> bool:
    """True if host is an IPv4/IPv6 literal (no registrable domain / crt.sh)."""
    import ipaddress
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registrable_hint(host: str) -> str:
    """Rough 'last two labels' apex guess (no PSL). e.g. a.b.example.com -> example.com"""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def in_scope(url: str, scope_hosts: set[str], include_subdomains: bool) -> bool:
    h = host_of(url)
    if not h:
        return False
    if h in scope_hosts:
        return True
    if include_subdomains:
        for s in scope_hosts:
            if h == s or h.endswith("." + s):
                return True
    return False


def split_params(url: str) -> tuple[str, dict[str, str]]:
    """Return (url_without_query, {param: value})."""
    p = urlparse(url)
    params = dict(parse_qsl(p.query, keep_blank_values=True))
    clean = urlunparse((p.scheme, p.netloc, p.path, p.params, "", ""))
    return clean, params


def dedupe_by_shape(urls: set[str]) -> list[str]:
    """Collapse URLs that share the same path+param-keys (ignore values)."""
    seen: dict[str, str] = {}
    for u in sorted(urls):
        clean, params = split_params(u)
        shape = clean + "?" + ",".join(sorted(params.keys())) if params else clean
        seen.setdefault(shape, u)
    return sorted(seen.values())


JS_URL_RE = re.compile(r"""\.js(\?[^"'\s]*)?$""", re.I)


def looks_like_js(url: str) -> bool:
    path = urlparse(url).path
    return bool(JS_URL_RE.search(path)) or path.endswith(".mjs")
