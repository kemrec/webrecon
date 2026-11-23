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
from webrecon.control import ScanStopped
from webrecon.http_client import HTTPClient


def _is_ip(token: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


async def run(cfg: ScanConfig, on_event=None, control=None) -> ScanResult:
    """Run the scan pipeline and return a ScanResult.

    `on_event`, if given, is a plain callable invoked with small JSON-able dicts
    as milestones are reached -- {"type":"start","nhosts":N} once hosts are
    discovered, then {"type":"host","host":<host.to_dict()>} as each host's
    fingerprint/exposure/CVE work completes. Between those coarse milestones it
    also emits high-level progress ticks {"type":"phase","phase":<name>,
    "host":<label>} at each sub-phase boundary (nmap / fingerprint / exposure /
    render / cve / web), so a live consumer can show what the scan is doing
    during the long silent stretches instead of a frozen label. Phase ticks
    carry no results and are advisory. It drives the web UI's live stream; it is
    best-effort (exceptions are swallowed) and never changes the result.
    """
    def _emit(ev):
        if on_event is not None:
            try:
                on_event(ev)
            except Exception:  # noqa: BLE001
                pass

    async def _ckpt():
        # cooperative pause/stop boundary; a stop raises ScanStopped (caught
        # below) so the scan returns the partial result it has so far.
        if control is not None:
            await control.checkpoint()

    tokens = cfg.targets or ([cfg.target] if cfg.target else [])
    result = ScanResult(target=cfg.target or " ".join(tokens))

    # ---- phase 1: discover hosts + open ports ----
    if cfg.use_nmap and nmap_engine.nmap_available(cfg.nmap_path):
        _emit({"type": "phase", "phase": "nmap"})
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
        _emit({"type": "start", "nhosts": 0})
        return result

    nhosts = sum(1 for h in hosts if h.services)
    _emit({"type": "start", "nhosts": nhosts})
    if nhosts > 1:
        utils.info(f"fingerprint + CVE across {nhosts} hosts")

    # ---- phase 2 + 3: fingerprint + CVE (per host, shared HTTP client) ----
    web_cfg = WebConfig(target=utils.ensure_scheme(tokens[0] if tokens else ""),
                        concurrency=cfg.concurrency, timeout=cfg.timeout,
                        verify_tls=False)
    http = HTTPClient(web_cfg)
    stopped = False
    try:
        for h in hosts:
            if not h.services:
                continue
            await _ckpt()                 # pause/stop boundary (between hosts)
            conn_host = h.ip or h.hostname
            if nhosts > 1:
                utils.info(f"host {h.label()}: {len(h.services)} open service(s)")
            label = h.label()
            if cfg.fingerprint:
                _emit({"type": "phase", "phase": "fingerprint", "host": label})
                await fingerprint.run_fingerprint(cfg, http, conn_host, h.services)
                _emit({"type": "phase", "phase": "exposure", "host": label})
                await fingerprint.run_exposure_checks(cfg, conn_host, h.services)
                await fingerprint.run_discovery_probes(cfg, http, conn_host,
                                                       h.services)
            if cfg.render:
                # render web-port roots to catch JS-global/DOM-only catalog apps
                # BEFORE CVE so their versioned hits correlate (opt-in).
                _emit({"type": "phase", "phase": "render", "host": label})
                await fingerprint.run_render_catalog(cfg, conn_host, h.services)
            if cfg.cve:
                await _ckpt()             # pause/stop before the long CVE step
                _emit({"type": "phase", "phase": "cve", "host": label})
                utils.info(f"correlating CVEs (NVD / OSV) for {h.label()}")
                await cve.correlate(cfg, http, h.services)
                # environmental refinement: demote ALPACA (CVE-2021-3618) on
                # FTP services that do not actually offer TLS (probes only the
                # services carrying that CVE).
                await cve.refine_ftp_alpaca(cfg, conn_host, h.services)
            _emit({"type": "host", "host": h.to_dict()})
    except ScanStopped:
        stopped = True
    finally:
        await http.close()

    # ---- optional phase 4: web chain (hand web ports to webrecon) ----
    if cfg.web and not stopped:
        from . import chain
        _emit({"type": "phase", "phase": "web"})
        utils.info("web chain: handing discovered web ports to webrecon")
        try:
            await chain.run_web_chain(cfg, result, control=control)
            # the chain enriches services with a `web` summary AFTER the per-host
            # events above were emitted, so push the enriched hosts once more for
            # any live consumer to replace what it rendered.
            _emit({"type": "update",
                   "hosts": [h.to_dict() for h in hosts if h.services]})
        except ScanStopped:
            stopped = True

    if stopped:
        _emit({"type": "phase", "phase": "stopped"})
        utils.warn("scan stopped by request; returning partial results")
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
