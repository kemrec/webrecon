"""nmap wrapper: run `nmap -sV` and parse its XML into Service objects.

We ask nmap for service+version detection and read its XML (-oX -). The XML
schema is stable across nmap versions: <host>/<ports>/<port>/<service> with
attributes name/product/version/extrainfo and nested <cpe> elements.
"""
from __future__ import annotations

import asyncio
import shutil
import xml.etree.ElementTree as ET

from .config import ScanConfig
from .models import Service, Host
from webrecon import utils


def nmap_available(path: str = "nmap") -> bool:
    return shutil.which(path) is not None


def build_argv(cfg: ScanConfig) -> list[str]:
    argv = [cfg.nmap_path, "-sV", "-Pn", "-T4", "-oX", "-"]
    if cfg.top_ports:
        argv += ["--top-ports", str(cfg.top_ports)]
    else:
        argv += ["-p", cfg.ports]
    if cfg.scan_rate:
        argv += ["--min-rate", str(cfg.scan_rate)]
    argv += cfg.nmap_args
    # nmap expands CIDR / ranges / lists natively; hand it every token
    argv += (cfg.targets or [cfg.target])
    return argv


async def run_nmap(cfg: ScanConfig) -> tuple[list[Host], str]:
    """Run nmap once over the whole spec, return ([Host], raw_xml). Never raises."""
    argv = build_argv(cfg)
    utils.info(f"nmap: {' '.join(argv)}")
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, errb = await proc.communicate()
    except FileNotFoundError:
        utils.warn("nmap not found on PATH")
        return [], ""
    except Exception as e:  # noqa: BLE001
        utils.err(f"nmap failed: {e}")
        return [], ""

    xml = out.decode("utf-8", "replace")
    if proc.returncode not in (0, 1):   # 1 can still carry partial results
        utils.debug(f"nmap rc={proc.returncode}: {errb.decode('utf-8','replace')[:200]}")
    hosts = parse_nmap_xml(xml)
    nsvc = sum(len(h.services) for h in hosts)
    utils.good(f"nmap: {nsvc} open service(s) across {len(hosts)} host(s)")
    return hosts, xml


def _parse_port(port) -> Service | None:
    state_el = port.find("state")
    state = state_el.get("state", "") if state_el is not None else ""
    if state != "open":
        return None
    svc_el = port.find("service")
    svc = Service(
        port=int(port.get("portid", "0")),
        proto=port.get("protocol", "tcp"),
        state=state,
        sources=["nmap"],
    )
    if svc_el is not None:
        svc.name = svc_el.get("name", "") or ""
        svc.product = svc_el.get("product", "") or ""
        svc.version = svc_el.get("version", "") or ""
        svc.extrainfo = svc_el.get("extrainfo", "") or ""
        tunnel = svc_el.get("tunnel", "")
        if tunnel == "ssl":
            svc.name = (svc.name or "https")
            svc.tls = {"tunnel": "ssl"}
        for cpe in svc_el.findall("cpe"):
            if cpe.text:
                svc.cpe.append(cpe.text)
        if svc.product and svc.version:
            svc.confidence = "high"
        elif svc.product or svc.name:
            svc.confidence = "medium"
    return svc


def _hostname_of(host_el) -> str:
    """Prefer the user-supplied name; fall back to PTR."""
    hns = host_el.find("hostnames")
    if hns is None:
        return ""
    user = ptr = ""
    for hn in hns.findall("hostname"):
        name = hn.get("name", "") or ""
        if not name:
            continue
        if hn.get("type") == "user" and not user:
            user = name
        elif not ptr:
            ptr = name
    return user or ptr


def parse_nmap_xml(xml: str) -> list[Host]:
    """Parse nmap XML into one Host per scanned machine (open ports only)."""
    hosts: list[Host] = []
    if not xml.strip():
        return hosts
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        utils.debug(f"nmap xml parse error: {e}")
        return hosts

    for host_el in root.findall("host"):
        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", ip)
                break
        if not ip:
            addr = host_el.find("address")
            ip = addr.get("addr", "") if addr is not None else ""
        hostname = _hostname_of(host_el)

        services: list[Service] = []
        ports = host_el.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                svc = _parse_port(port)
                if svc is not None:
                    services.append(svc)
        services.sort(key=lambda s: s.port)

        if services:
            hosts.append(Host(target=hostname or ip, ip=ip,
                              hostname=hostname, services=services))

    return hosts


def needs_fingerprint(svc: Service) -> bool:
    """True if nmap left this service under-identified (no product or version)."""
    if not svc.product:
        return True
    if not svc.version:
        return True
    return False
