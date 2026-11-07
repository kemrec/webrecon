"""servicescan pipeline: nmap -> fingerprint gap-fill -> CVE correlation."""
from __future__ import annotations

from .config import ScanConfig
from .models import ScanResult, Service
from . import nmap_engine, fingerprint, cve
from webrecon import utils
from webrecon.config import Config as WebConfig
from webrecon.http_client import HTTPClient


async def run(cfg: ScanConfig) -> ScanResult:
    host = utils.host_of(utils.ensure_scheme(cfg.target)) or cfg.target
    result = ScanResult(target=cfg.target)

    # ---- phase 1: nmap (if available & enabled) ----
    services: list[Service] = []
    if cfg.use_nmap and nmap_engine.nmap_available(cfg.nmap_path):
        ip, services, _xml = await nmap_engine.run_nmap(cfg)
        result.ip = ip
        result.nmap_used = True
    else:
        if cfg.use_nmap:
            utils.warn("nmap not available — falling back to fingerprint-only "
                       "on common ports")
            result.errors.append("nmap not found; limited port coverage")
        services = _fallback_ports(cfg)

    if not services:
        utils.warn("no open services found")
        result.services = []
        return result

    # ---- phase 2 + 3: fingerprint + CVE need an HTTP client ----
    web_cfg = WebConfig(target=utils.ensure_scheme(cfg.target),
                        concurrency=cfg.concurrency, timeout=cfg.timeout,
                        verify_tls=False)
    http = HTTPClient(web_cfg)
    try:
        if cfg.fingerprint:
            await fingerprint.run_fingerprint(cfg, http, host, services)
        if cfg.cve:
            utils.info("correlating CVEs (NVD / OSV)")
            await cve.correlate(cfg, http, services)
    finally:
        await http.close()

    result.services = services
    return result


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
