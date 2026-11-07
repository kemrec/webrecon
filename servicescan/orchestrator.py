"""servicescan pipeline: nmap -> fingerprint gap-fill -> CVE correlation.

Works over one or many hosts: the target spec may be a single IP/hostname, a
comma/space separated list, a CIDR block, or an nmap-style range. nmap expands
these in a single scan; each resulting host then runs the fingerprint + CVE
(+ optional web) pipeline independently.
"""
from __future__ import annotations

from .config import ScanConfig
from .models import ScanResult, Service, Host
from . import nmap_engine, fingerprint, cve, targets
from webrecon import utils
from webrecon.config import Config as WebConfig
from webrecon.http_client import HTTPClient


def _is_ip(token: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


async def run(cfg: ScanConfig) -> ScanResult:
    tokens = cfg.targets or ([cfg.target] if cfg.target else [])
    result = ScanResult(target=cfg.target or " ".join(tokens))

    # ---- phase 1: discover hosts + open ports ----
    if cfg.use_nmap and nmap_engine.nmap_available(cfg.nmap_path):
        hosts, _xml = await nmap_engine.run_nmap(cfg)
        result.nmap_used = True
    else:
        if cfg.use_nmap:
            utils.warn("nmap not available — falling back to fingerprint-only "
                       "on common ports")
            result.errors.append("nmap not found; limited port coverage")
        hosts = _fallback_hosts(cfg, tokens)

    result.hosts = hosts
    if not any(h.services for h in hosts):
        utils.warn("no open services found")
        return result

    nhosts = sum(1 for h in hosts if h.services)
    if nhosts > 1:
        utils.info(f"fingerprint + CVE across {nhosts} hosts")

    # ---- phase 2 + 3: fingerprint + CVE (per host, shared HTTP client) ----
    web_cfg = WebConfig(target=utils.ensure_scheme(tokens[0] if tokens else ""),
                        concurrency=cfg.concurrency, timeout=cfg.timeout,
                        verify_tls=False)
    http = HTTPClient(web_cfg)
    try:
        for h in hosts:
            if not h.services:
                continue
            conn_host = h.ip or h.hostname
            if nhosts > 1:
                utils.info(f"host {h.label()}: {len(h.services)} open service(s)")
            if cfg.fingerprint:
                await fingerprint.run_fingerprint(cfg, http, conn_host, h.services)
            if cfg.cve:
                utils.info(f"correlating CVEs (NVD / OSV) for {h.label()}")
                await cve.correlate(cfg, http, h.services)
    finally:
        await http.close()

    # ---- optional phase 4: web chain (hand web ports to webrecon) ----
    if cfg.web:
        from . import chain
        utils.info("web chain: handing discovered web ports to webrecon")
        await chain.run_web_chain(cfg, result)

    return result


def _fallback_hosts(cfg: ScanConfig, tokens: list[str]) -> list[Host]:
    """No-nmap path: expand the spec ourselves and seed common ports per host."""
    hosts: list[Host] = []
    for tok in targets.expand(tokens):
        h = Host(target=tok)
        if _is_ip(tok):
            h.ip = tok
        else:
            h.hostname = tok
        h.services = _fallback_ports(cfg)
        hosts.append(h)
    return hosts


def _fallback_ports(cfg: ScanConfig) -> list[Service]:
    """When nmap is unavailable, seed a set of common ports to fingerprint."""
    common = [21, 22, 25, 80, 110, 143, 443, 3306, 5432, 6379,
              8000, 8080, 8443, 8888]
    # honor an explicit -p list if it's simple comma form
    if cfg.ports not in ("-", ""):
        try:
            common = []
            for part in cfg.ports.split(","):
                part = part.strip()
                if "-" in part:
                    a, b = part.split("-", 1)
                    common.extend(range(int(a), int(b) + 1))
                elif part:
                    common.append(int(part))
        except ValueError:
            pass
    return [Service(port=p, sources=["fallback"], confidence="low")
            for p in common]
