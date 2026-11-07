"""Subdomain enumeration, TLS certificate SAN extraction, and vhost discovery.

- Passive subdomain enum via crt.sh (certificate transparency logs).
- TLS cert SAN pull: connect to the target, read the leaf cert, harvest
  subjectAltName DNS entries -> these are prime vhost / subdomain candidates.
- Vhost discovery: against a single resolved IP, send requests with different
  Host: headers (candidates from certs, crt.sh, wordlist) and flag hosts whose
  response differs from the default/baseline (classic virtual-host fuzzing).
"""
from __future__ import annotations

import asyncio
import json
import socket
import ssl
from dataclasses import dataclass, field

from .config import Config
from .http_client import HTTPClient
from . import utils


# ---------------------------------------------------------------------------
# TLS certificate SAN extraction
# ---------------------------------------------------------------------------
def cert_sans(host: str, port: int = 443, timeout: float = 8.0) -> list[str]:
    """Connect, grab leaf cert, return list of DNS SAN names (lowercased)."""
    names: set[str] = set()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # getpeercert(binary_form=False) needs verify; parse DER instead
                der = ssock.getpeercert(binary_form=True)
        names |= _parse_der_sans(der)
    except Exception as e:  # noqa: BLE001
        utils.debug(f"cert_sans {host}: {type(e).__name__}: {e}")
    return sorted(n.lower().lstrip("*.") for n in names if n)


def _parse_der_sans(der: bytes) -> set[str]:
    """Extract SAN dNSNames from a DER cert using the cryptography lib."""
    out: set[str] = set()
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID
        cert = x509.load_der_x509_certificate(der)
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            from cryptography.x509 import DNSName
            for n in ext.value.get_values_for_type(DNSName):
                out.add(n)
        except Exception:
            pass
        # common name fallback
        try:
            from cryptography.x509.oid import NameOID
            for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                out.add(attr.value)
        except Exception:
            pass
    except Exception as e:  # noqa: BLE001
        utils.debug(f"der parse: {e}")
    return out


# ---------------------------------------------------------------------------
# Passive subdomain enum via crt.sh
# ---------------------------------------------------------------------------
async def crtsh_subdomains(http: HTTPClient, apex: str) -> set[str]:
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    r = await http.fetch(url)
    subs: set[str] = set()
    if not r.ok or not r.text:
        utils.debug("crt.sh returned nothing")
        return subs
    try:
        data = json.loads(r.text)
        for row in data:
            for field_name in ("name_value", "common_name"):
                val = row.get(field_name, "")
                for name in str(val).split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(apex) and all(
                        c.isalnum() or c in ".-" for c in name
                    ):
                        subs.add(name)
    except Exception as e:  # noqa: BLE001
        utils.debug(f"crt.sh parse: {e}")
    return subs


# ---------------------------------------------------------------------------
# DNS resolution helper (dnspython optional, fallback to socket)
# ---------------------------------------------------------------------------
def resolve(host: str) -> set[str]:
    ips: set[str] = set()
    try:
        import dns.resolver  # type: ignore
        for rtype in ("A", "AAAA"):
            try:
                for a in dns.resolver.resolve(host, rtype, lifetime=5):
                    ips.add(a.to_text())
            except Exception:
                pass
    except ImportError:
        try:
            for res in socket.getaddrinfo(host, None):
                ips.add(res[4][0])
        except Exception:
            pass
    return ips


async def resolve_many(hosts: set[str], concurrency: int = 50) -> dict[str, set[str]]:
    sem = asyncio.Semaphore(concurrency)
    out: dict[str, set[str]] = {}

    async def one(h: str):
        async with sem:
            ips = await asyncio.to_thread(resolve, h)
            if ips:
                out[h] = ips

    await asyncio.gather(*(one(h) for h in hosts))
    return out


# ---------------------------------------------------------------------------
# Vhost discovery (Host-header fuzzing against a fixed IP)
# ---------------------------------------------------------------------------
@dataclass
class VhostResult:
    ip: str
    baseline_status: int = 0
    baseline_len: int = 0
    found: list[dict] = field(default_factory=list)   # {host, status, length}


async def vhost_scan(http: HTTPClient, ip: str, scheme: str,
                     candidates: set[str]) -> VhostResult:
    """Send requests to `ip` with varied Host headers; flag divergent responses."""
    base_url = f"{scheme}://{ip}/"
    res = VhostResult(ip=ip)

    # baseline with a random/nonexistent host
    rnd = "zzz-nonexistent-vhost-1337"
    base = await http.head_or_get(base_url, host_header=rnd)
    res.baseline_status = base.status
    # use a GET for length baseline
    base_get = await http.fetch(base_url, method="GET",
                                headers={"Host": rnd}, read_body=True)
    res.baseline_len = len(base_get.text or "")

    async def probe(host: str):
        r = await http.fetch(base_url, method="GET",
                             headers={"Host": host}, read_body=True)
        if not r.ok:
            return
        length = len(r.text or "")
        # divergence heuristic: different status, or length differs > 5%
        diff_status = r.status != res.baseline_status
        diff_len = (res.baseline_len == 0 and length > 0) or (
            res.baseline_len > 0 and abs(length - res.baseline_len) / max(res.baseline_len, 1) > 0.05
        )
        if (diff_status or diff_len) and r.status not in (0,):
            res.found.append({"host": host, "status": r.status, "length": length})
            utils.hit(f"vhost on {ip}: {host} -> {r.status} ({length}b)")

    await asyncio.gather(*(probe(h) for h in candidates))
    return res


# ---------------------------------------------------------------------------
# Orchestration entry for the discovery phase
# ---------------------------------------------------------------------------
@dataclass
class DiscoveryResult:
    apex: str
    cert_sans: list[str] = field(default_factory=list)
    crtsh_subs: list[str] = field(default_factory=list)
    resolved: dict[str, list[str]] = field(default_factory=dict)  # host -> ips
    vhosts: list[dict] = field(default_factory=list)              # {ip, host, status, length}
    all_hosts: list[str] = field(default_factory=list)


async def run_discovery(cfg: Config, http: HTTPClient,
                        primary_host: str, seed_hosts: set[str]) -> DiscoveryResult:
    apex = utils.registrable_hint(primary_host)
    dr = DiscoveryResult(apex=apex)
    candidates: set[str] = set(seed_hosts) | {primary_host}

    # 1) cert SANs (sync in thread)
    if cfg.do_vhost or cfg.do_subdomains:
        utils.info(f"pulling TLS cert SANs for {primary_host}")
        sans = await asyncio.to_thread(cert_sans, primary_host)
        dr.cert_sans = sans
        candidates |= set(sans)
        if sans:
            utils.good(f"cert SANs: {len(sans)} names")

    # 2) crt.sh passive subdomains
    if cfg.do_subdomains:
        utils.info(f"querying crt.sh for *.{apex}")
        subs = await crtsh_subdomains(http, apex)
        dr.crtsh_subs = sorted(subs)
        candidates |= subs
        utils.good(f"crt.sh subdomains: {len(subs)}")

    # 3) optional wordlist
    if cfg.subdomain_wordlist:
        try:
            with open(cfg.subdomain_wordlist, encoding="utf-8", errors="ignore") as fh:
                for w in fh:
                    w = w.strip()
                    if w and not w.startswith("#"):
                        candidates.add(f"{w}.{apex}")
        except OSError as e:
            utils.warn(f"subdomain wordlist: {e}")
    if cfg.vhost_wordlist:
        try:
            with open(cfg.vhost_wordlist, encoding="utf-8", errors="ignore") as fh:
                for w in fh:
                    w = w.strip()
                    if w and not w.startswith("#"):
                        candidates.add(w if "." in w else f"{w}.{apex}")
        except OSError as e:
            utils.warn(f"vhost wordlist: {e}")

    candidates = {c for c in candidates if c and "." in c}
    dr.all_hosts = sorted(candidates)

    # 4) resolve all candidates
    if cfg.do_subdomains or cfg.do_vhost:
        utils.info(f"resolving {len(candidates)} candidate hosts")
        resolved = await resolve_many(candidates, concurrency=cfg.concurrency)
        dr.resolved = {h: sorted(ips) for h, ips in resolved.items()}
        utils.good(f"resolved {len(resolved)} hosts")

    # 5) vhost scan: group by IP, fuzz Host header for unresolved/wildcard names
    if cfg.do_vhost and dr.resolved:
        scheme = "https" if cfg.target.startswith("https") else "http"
        # IPs belonging to the primary host are the vhost targets
        primary_ips = set(dr.resolved.get(primary_host, []))
        if not primary_ips:
            # use any resolved IP of apex
            primary_ips = set(dr.resolved.get(apex, []))
        target_ips = primary_ips or {ip for ips in dr.resolved.values() for ip in ips}
        # candidate Host values: all known hostnames (test which the shared IP serves)
        host_cands = candidates
        for ip in list(target_ips)[:5]:   # cap to avoid scanning huge sets
            utils.info(f"vhost fuzzing against {ip} ({len(host_cands)} hosts)")
            vr = await vhost_scan(http, ip, scheme, host_cands)
            for f in vr.found:
                dr.vhosts.append({"ip": ip, **f})

    return dr
