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
    if getattr(cfg, "udp", False):
        argv.append("-sU")                # UDP service scan (needs root, slow)
    if getattr(cfg, "nse", False):
        argv += ["--script", cfg.nse_scripts or "vuln"]
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
    # TCP: only "open"; UDP commonly reports "open|filtered" — keep those too
    if not (state == "open" or state.startswith("open")):
        return None
    svc = Service(
        port=int(port.get("portid", "0")),
        proto=port.get("protocol", "tcp"),
        state=state,
        sources=["nmap"],
    )
    # NSE script output attached to this port (--script / --nse)
    for sc in port.findall("script"):
        out = (sc.get("output") or "").strip()
        if out:
            svc.scripts.append({"id": sc.get("id", ""), "output": out[:2000]})
    svc_el = port.find("service")
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


# nmap fingerprints a Tomcat HTTP connector as the Coyote engine and reports the
# connector's *protocol* version, not the Tomcat server version, e.g.
#   product="Apache Tomcat/Coyote JSP engine" version="1.1"
#   cpe=cpe:/a:apache:coyote_http_connector:1.1
# That "1.1" is the Coyote/HTTP connector version; the real Tomcat version is a
# wholly different, often very old number. Worse, coyote_http_connector is an
# all-but-empty NVD product, so correlating it yields zero CVEs while silently
# discarding a genuinely vulnerable Tomcat. We must recover the true version
# (and never correlate against "1.1", which — being far below every Tomcat
# version bound — would match nearly every Tomcat CVE => false positives).
_COYOTE_CPE_PRODUCTS = ("coyote_http_connector", "coyote_jsp_engine")


def is_coyote_misattrib(svc: Service) -> bool:
    """True if nmap labelled this service as the Coyote connector (so its
    product is really Tomcat and its reported version is the protocol version,
    not the server version)."""
    pl = (svc.product or "").lower()
    if "tomcat" in pl and "coyote" in pl:
        return True
    return any(p in (c or "").lower()
               for c in svc.cpe for p in _COYOTE_CPE_PRODUCTS)


def needs_fingerprint(svc: Service) -> bool:
    """True if nmap left this service under-identified (no product or version),
    or mis-attributed it as the Coyote connector (product+version both set, but
    the version is the connector protocol version, not Tomcat's)."""
    if not svc.product:
        return True
    if not svc.version:
        return True
    if is_coyote_misattrib(svc):
        return True
    return False
