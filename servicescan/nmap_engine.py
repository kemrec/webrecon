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
from .models import Service
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
    argv.append(cfg.target)
    return argv


async def run_nmap(cfg: ScanConfig) -> tuple[str, list[Service], str]:
    """Run nmap, return (resolved_ip, services, raw_xml). Never raises."""
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
        return "", [], ""
    except Exception as e:  # noqa: BLE001
        utils.err(f"nmap failed: {e}")
        return "", [], ""

    xml = out.decode("utf-8", "replace")
    if proc.returncode not in (0, 1):   # 1 can still carry partial results
        utils.debug(f"nmap rc={proc.returncode}: {errb.decode('utf-8','replace')[:200]}")
    ip, services = parse_nmap_xml(xml)
    utils.good(f"nmap: {len(services)} open services on {ip or cfg.target}")
    return ip, services, xml


def parse_nmap_xml(xml: str) -> tuple[str, list[Service]]:
    """Parse nmap XML text into (ip, [Service])."""
    services: list[Service] = []
    ip = ""
    if not xml.strip():
        return ip, services
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        utils.debug(f"nmap xml parse error: {e}")
        return ip, services

    for host in root.findall("host"):
        addr = host.find("address")
        if addr is not None:
            ip = addr.get("addr", ip)
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state_el = port.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state != "open":
                continue
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
                # nmap's own confidence (conf 0-10 attr)
                conf = svc_el.get("conf", "")
                if svc.product and svc.version:
                    svc.confidence = "high"
                elif svc.product or svc.name:
                    svc.confidence = "medium"
            services.append(svc)

    services.sort(key=lambda s: s.port)
    return ip, services


def needs_fingerprint(svc: Service) -> bool:
    """True if nmap left this service under-identified (no product or version)."""
    if not svc.product:
        return True
    if not svc.version:
        return True
    return False
