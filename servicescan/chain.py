"""--web chain: hand servicescan's discovered HTTP(S) ports to webrecon.

The pivot that makes this useful on internal networks: public CT logs
(crt.sh) are empty for private zones, but the TLS certificate presented on a
scanned port very often carries SANs for other internal names that exist
*only* in the cert (e.g. an admin or staging vhost). We harvest those SANs
across every TLS service, map each one to the scanned IP (so it is reachable
without DNS or /etc/hosts), and run webrecon against every web port with those
names injected as vhost candidates. webrecon then Host-header-fuzzes them
against the IP and crawls whatever answers.
"""
from __future__ import annotations

import os

from .config import ScanConfig
from .models import ScanResult, Service, Host
from . import fingerprint
from webrecon import utils
from webrecon.config import Config as WebConfig
from webrecon import orchestrator as web_orch, report as web_report


_WEB_NAMES = ("http", "https", "http-alt", "http-proxy", "https-alt")
_HOSTS_MARK = "# servicescan --web (cert SANs)"


def _is_web(svc: Service) -> bool:
    name = (svc.name or "").lower()
    return (any(n in name for n in ("http",))
            or bool(svc.http)
            or svc.port in fingerprint._HTTP_PORTS
            or svc.port in fingerprint._TLS_PORTS)


def _is_tls(svc: Service) -> bool:
    name = (svc.name or "").lower()
    return ("https" in name or "ssl" in name
            or bool(svc.tls) or svc.port in fingerprint._TLS_PORTS)


def _clean_host(name: str) -> str:
    n = (name or "").strip().lower().rstrip(".").lstrip("*.")
    return n


def harvest_sans(services: list[Service]) -> list[str]:
    """Collect DNS names from every service's TLS cert (SANs + subject CN)."""
    out: set[str] = set()
    for svc in services:
        tls = svc.tls or {}
        for n in tls.get("sans", []) or []:
            out.add(_clean_host(n))
        cn = _clean_host(tls.get("subject_cn", ""))
        if cn:
            out.add(cn)
    # keep plausible hostnames only
    return sorted(h for h in out
                  if h and "." in h and all(c.isalnum() or c in ".-" for c in h))


def _write_hosts(ip: str, hosts: list[str]) -> None:
    if not hosts:
        return
    line = f"{ip}\t{' '.join(hosts)}\t{_HOSTS_MARK}\n"
    try:
        with open("/etc/hosts", "a", encoding="utf-8") as fh:
            fh.write(line)
        utils.good(f"wrote {len(hosts)} host(s) -> {ip} to /etc/hosts")
    except PermissionError:
        utils.warn("write-hosts: need root to edit /etc/hosts (skipped)")
    except OSError as e:
        utils.warn(f"write-hosts: {e}")


def _safe_seg(name: str) -> str:
    return "".join(c if (c.isalnum() or c in ".-") else "_" for c in name)


async def run_web_chain(cfg: ScanConfig, result: ScanResult) -> None:
    web_hosts = [h for h in result.hosts
                 if any(s.state == "open" and _is_web(s) for s in h.services)]
    if not web_hosts:
        utils.info("web chain: no HTTP(S) ports found, nothing to hand off")
        return
    multi = len([h for h in result.hosts if h.services]) > 1
    for h in web_hosts:
        await _chain_host(cfg, h, multi)


async def _chain_host(cfg: ScanConfig, host: Host, multi: bool) -> None:
    ip = host.ip or ""
    # use the hostname form if we have one, else the IP.
    target_host = host.hostname or ip
    is_ip_target = not host.hostname

    web_svcs = [s for s in host.services if s.state == "open" and _is_web(s)]
    if not web_svcs:
        return
    if multi:
        utils.info(f"web chain: host {host.label()} "
                   f"({len(web_svcs)} web port(s))")

    # ensure every TLS web port has its cert grabbed, even when nmap already
    # identified the service (the fingerprint gap-fill layer skips those, so
    # svc.tls — and thus the SANs we pivot on — would otherwise be empty).
    cert_host = ip or target_host
    for svc in web_svcs:
        if _is_tls(svc) and not svc.tls:
            t = await fingerprint.tls_info(cert_host, svc.port, cfg.timeout)
            if t:
                svc.tls.update(t)

    sans = harvest_sans(host.services)
    if sans:
        utils.good(f"web chain: harvested {len(sans)} cert SAN host(s) "
                   f"to pivot on ({host.label()})")

    # every harvested name (and the primary hostname) resolves to the scanned IP
    resolve_map: dict[str, str] = {}
    if ip:
        for s in sans:
            resolve_map[s] = ip
        if not is_ip_target:
            resolve_map.setdefault(target_host, ip)

    if cfg.write_hosts and ip:
        _write_hosts(ip, sans)

    seed_host = target_host if not is_ip_target else ip
    extra = set(sans)
    # per-host output dir segment so multiple hosts don't collide
    host_seg = _safe_seg(ip or target_host)

    for svc in web_svcs:
        tls = _is_tls(svc)
        scheme = "https" if tls else "http"
        url = f"{scheme}://{seed_host}:{svc.port}/"
        utils.info(f"web chain: webrecon {url} "
                   f"(+{len(extra)} cert-SAN vhost candidates)")

        if multi:
            outdir = os.path.join(cfg.outdir, "web", host_seg, f"{svc.port}-{scheme}")
        else:
            outdir = os.path.join(cfg.outdir, "web", f"{svc.port}-{scheme}")

        wcfg = WebConfig(
            target=url,
            depth=cfg.web_depth,
            max_pages=cfg.web_max_pages,
            render=cfg.web_render,
            concurrency=cfg.concurrency,
            timeout=cfg.timeout,
            verify_tls=False,
            resolve_map=dict(resolve_map),
            extra_hosts=extra,
            outdir=outdir,
            quiet=True,
        )
        # pivot on cert SANs, not public CT logs: skip crt.sh, keep vhost fuzz
        wcfg.do_subdomains = False
        wcfg.scope_hosts = {seed_host} | ({ip} if ip else set()) | extra

        try:
            data = await web_orch.run(wcfg)
        except Exception as e:  # noqa: BLE001
            utils.warn(f"web chain {url}: {type(e).__name__}: {e}")
            continue

        # persist the full per-port webrecon output, keep a compact summary on svc
        try:
            web_report.write_all(wcfg.outdir, data)
        except Exception as e:  # noqa: BLE001
            utils.debug(f"web chain report {url}: {e}")

        svc.web = {
            "url": url,
            "scheme": scheme,
            "outdir": wcfg.outdir,
            "pages": len(data.get("pages", {})),
            "urls": len(data.get("urls", [])),
            "endpoints": len(data.get("endpoints", [])),
            "params": len(data.get("params", {})),
            "vhosts": data.get("vhosts", []),
            "secrets": len(data.get("secrets", [])),
            "subdomains": data.get("subdomains", []),
        }
        nv = len(svc.web["vhosts"])
        if nv:
            utils.hit(f":{svc.port} web chain found {nv} vhost(s) on {ip or seed_host}")
