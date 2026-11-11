"""Our own fingerprinting layer — fills gaps nmap leaves.

Three complementary probes per target port:
  1. TCP banner grab       — connect, read whatever the service greets with,
                             optionally send a protocol-appropriate nudge.
  2. HTTP fingerprint      — Server header, X-Powered-By, generator meta,
                             body regexes for common web apps/frameworks.
  3. TLS certificate       — subject/issuer/SAN (helps name the host & app).

Each probe emits (product, version, source, confidence) candidates; merge_into
folds the best of them onto the Service, preferring more specific / higher
confidence evidence without discarding nmap's result when it was already good.
"""
from __future__ import annotations

import asyncio
import re
import ssl

from .config import ScanConfig
from .models import Service
from webrecon import utils


# ---------------------------------------------------------------------------
# Banner -> (product, version) signatures
# ---------------------------------------------------------------------------
_BANNER_SIGS = [
    # ssh
    (re.compile(r"SSH-\d+\.\d+-OpenSSH[_-]([0-9][0-9a-zA-Z._-]*)", re.I),
     "OpenSSH", 1),
    (re.compile(r"SSH-\d+\.\d+-(?:dropbear)[_-]?([0-9][0-9a-zA-Z._-]*)", re.I),
     "Dropbear SSH", 1),
    # ftp
    (re.compile(r"220.*vsFTPd\s+([0-9][0-9a-zA-Z._-]*)", re.I), "vsftpd", 1),
    (re.compile(r"220.*ProFTPD\s+([0-9][0-9a-zA-Z._-]*)", re.I), "ProFTPD", 1),
    (re.compile(r"220.*FileZilla Server\s+([0-9][0-9a-zA-Z._-]*)", re.I),
     "FileZilla Server", 1),
    # smtp
    (re.compile(r"220.*Postfix", re.I), "Postfix", 0),
    (re.compile(r"220.*Exim\s+([0-9][0-9a-zA-Z._-]*)", re.I), "Exim", 1),
    (re.compile(r"220.*Microsoft ESMTP MAIL Service.*?([0-9][0-9.]+)", re.I),
     "Microsoft Exchange SMTP", 1),
    # databases
    (re.compile(r"([0-9]+\.[0-9]+\.[0-9]+[0-9a-zA-Z.\-]*)-MariaDB", re.I),
     "MariaDB", 1),
    (re.compile(r"\x00?([0-9]+\.[0-9]+\.[0-9]+)[\x00-\x20].*mysql", re.I | re.S),
     "MySQL", 1),
    (re.compile(r"Redis.*?version[:=]?\s*([0-9][0-9.]+)", re.I), "Redis", 1),
    # rdp / other
    (re.compile(r"RFB\s+([0-9]{3}\.[0-9]{3})", re.I), "VNC (RFB)", 1),
]

# generic "name/1.2.3" token inside a banner
_GENERIC_VER = re.compile(r"\b([A-Za-z][A-Za-z0-9+._-]{1,30})/([0-9][0-9A-Za-z._-]+)")

# protocol nudges keyed by port -> bytes to send after connect
_NUDGE = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    6379: b"INFO\r\n",            # redis
    25: b"EHLO servicescan\r\n",
    110: b"",                     # pop3 greets on connect
}


async def banner_grab(host: str, port: int, timeout: float) -> str:
    """Connect, optionally nudge, read up to ~2KB. Returns decoded snippet."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except Exception as e:  # noqa: BLE001
        utils.debug(f"banner {host}:{port} connect fail: {type(e).__name__}")
        return ""
    data = b""
    try:
        # first, passive read (many services greet immediately)
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=min(3.0, timeout))
        except asyncio.TimeoutError:
            data = b""
        # if nothing, send a nudge and read again
        if not data and port in _NUDGE:
            writer.write(_NUDGE[port])
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            except asyncio.TimeoutError:
                pass
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass
    return data.decode("latin-1", "replace").strip()


def parse_banner(banner: str):
    """Return (product, version, confidence) from a banner, or ('','','')."""
    if not banner:
        return "", "", ""
    for rx, product, grp in _BANNER_SIGS:
        m = rx.search(banner)
        if m:
            ver = m.group(1) if grp and m.lastindex and m.lastindex >= grp else ""
            return product, ver, "high"
    # UnrealIRCd advertises distinctive ISUPPORT tokens even without a version
    # string (so nmap labels it 'irc' / product only). Confirm the product.
    if _IRC_UNREAL.search(banner):
        m = re.search(r"UnrealIRCd[-_ ]?([0-9][0-9a-zA-Z._-]*)", banner, re.I)
        return "UnrealIRCd", (m.group(1) if m else ""), "high" if m else "medium"
    # generic name/version
    m = _GENERIC_VER.search(banner)
    if m and m.group(1).lower() not in ("http", "https"):
        return m.group(1), m.group(2), "medium"
    return "", "", ""


# ---------------------------------------------------------------------------
# interactive shell / bindshell detection (MSF2 ingreslock 1524 etc.)
# A service that answers with a shell prompt or `id` output on connect is an
# unauthenticated remote command shell -- the single worst finding on a host,
# yet nmap routinely labels it 'unknown'. Match the prompt tail (unix user@host
# prompt, a Windows version banner / drive prompt) or classic id(1) output.
# ---------------------------------------------------------------------------
# High-confidence only (universal code must not false-positive on other
# services): a real user@host:path prompt, a Windows version/drive-prompt, or
# id(1) output. A bare trailing '$'/'#' is deliberately NOT matched -- far too
# many protocols end a line that way.
_SHELL_UNIX = re.compile(r"(?:^|\n|\x07)\s*[\w.\-]+@[\w.\-]+:[~/][^\n]*[#$]\s*$")
_SHELL_WIN = re.compile(r"Microsoft Windows \[Version|(?:^|\n)[A-Za-z]:\\[^\n]*>\s*$", re.M)
_ID_OUTPUT = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+")
_IRC_UNREAL = re.compile(r"(?=.*\bNAMESX\b)(?=.*\bWATCHOPTS\b)|\bUnrealIRCd\b",
                         re.I | re.S)


def detect_shell(banner: str) -> bool:
    """True if a banner looks like an open interactive command shell."""
    if not banner:
        return False
    b = banner.strip()
    return bool(_SHELL_UNIX.search(b) or _SHELL_WIN.search(b)
                or _ID_OUTPUT.search(b))


# ---------------------------------------------------------------------------
# AJP13 (Apache JServ Protocol) detection
# The Tomcat/JBoss AJP connector (classically port 8009) is a binary protocol
# that stays silent on a plain connect, so banner grabbing leaves it 'unknown'.
# A single CPing control packet elicits a CPong, whose 'AB' magic is a
# definitive, non-destructive identification (no request is processed).
# ---------------------------------------------------------------------------
_AJP_CPING = b"\x12\x34\x00\x01\x0a"   # magic 0x1234 | len 1 | prefix 0x0a (CPing)
_AJP_MAGIC = b"\x41\x42"               # 'AB' = server->container packet prefix


async def ajp_probe(host: str, port: int, timeout: float) -> bool:
    """True if the port speaks AJP13 (answers a CPing with a CPong)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:  # noqa: BLE001
        return False
    data = b""
    try:
        writer.write(_AJP_CPING)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(16), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass
    return data[:2] == _AJP_MAGIC


async def irc_probe(host: str, port: int, timeout: float) -> str:
    """IRC servers greet on connect but withhold the version; a VERSION command
    elicits the ISUPPORT/351 numerics that identify (Unreal)IRCd. Returns the
    greeting + VERSION reply, or ''."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:  # noqa: BLE001
        return ""
    data = b""
    try:
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=min(3.0, timeout))
        except asyncio.TimeoutError:
            pass
        writer.write(b"VERSION\r\n")
        await writer.drain()
        try:
            data += await asyncio.wait_for(reader.read(2048), timeout=timeout)
        except asyncio.TimeoutError:
            pass
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass
    return data.decode("latin-1", "replace").strip()


# ---------------------------------------------------------------------------
# HTTP fingerprint
# ---------------------------------------------------------------------------
_HTTP_BODY_SIGS = [
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I),
     None),  # generator meta -> raw
    (re.compile(r"/wp-content/|wp-includes|WordPress\s+([0-9.]+)", re.I), "WordPress"),
    (re.compile(r'name="generator"\s+content="Joomla', re.I), "Joomla"),
    (re.compile(r"Drupal\.settings|/sites/default/files", re.I), "Drupal"),
    (re.compile(r"X-Atlassian|jira|confluence", re.I), "Atlassian"),
    (re.compile(r"grafana", re.I), "Grafana"),
]
_SERVER_VER = re.compile(r"^([A-Za-z0-9+._-]+)(?:/([0-9][0-9A-Za-z._-]+))?")

# secondary products a web server advertises alongside itself (X-Powered-By,
# and some Server-header co-tokens). These run on the SAME port as the primary
# server (e.g. Apache) but are separate CVE subjects (PHP, ASP.NET, OpenSSL):
# the service carries one product, so without this they are never correlated.
_POWERED_RX = re.compile(r"([A-Za-z][A-Za-z.+#-]{1,20})(?:/([0-9][0-9.]*))?")


def _norm_ver(v: str) -> str:
    """Strip distro/build suffixes: '5.2.4-2ubuntu5.10' -> '5.2.4' (keeps NVD
    CPE matching from failing on the packaged version string)."""
    m = re.match(r"\d+(?:\.\d+){0,3}", v or "")
    return m.group(0) if m else ""


def parse_powered(powered: str) -> list[list[str]]:
    """Parse an X-Powered-By (or similar) header into [[product, version], ...].
    Only well-formed name[/version] tokens are kept; version is normalized."""
    out: list[list[str]] = []
    for tok in (powered or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        m = _POWERED_RX.match(tok)
        if not m:
            continue
        name = m.group(1).strip()
        ver = _norm_ver(m.group(2) or "")
        if name.lower() in ("servlet", "jsp"):   # too generic for CVE lookup
            continue
        pair = [name, ver]
        if pair not in out:
            out.append(pair)
    return out


async def http_fingerprint(http, host: str, port: int, tls: bool):
    """Return dict with server/version/title/tech + (product,version,conf)."""
    scheme = "https" if tls else "http"
    url = f"{scheme}://{host}:{port}/"
    r = await http.fetch(url, method="GET", read_body=True)
    info = {"url": url}
    if not r.ok or r.status == 0:
        return info, ("", "", "")
    server = r.headers.get("server", "").split(",")[0].strip()
    powered = r.headers.get("x-powered-by", "").split(",")[0].strip()
    info["status"] = r.status
    info["server"] = server
    if powered:
        info["x_powered_by"] = powered
    aux = parse_powered(powered)
    if aux:
        info["aux"] = aux
    m = re.search(r"<title[^>]*>(.*?)</title>", r.text or "", re.I | re.S)
    if m:
        info["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:120]

    product = version = ""
    conf = ""
    # Server header is the strongest signal
    sm = _SERVER_VER.match(server)
    if sm:
        product = sm.group(1)
        version = sm.group(2) or ""
        conf = "high" if version else "medium"
    # app-level body/header signatures (may override generic server like nginx)
    tech = []
    body = r.text or ""
    for rx, label in _HTTP_BODY_SIGS:
        m = rx.search(body) or rx.search(server + " " + powered)
        if m:
            if label is None:  # generator meta
                gen = m.group(1).strip()
                tech.append(gen)
                gm = re.match(r"([A-Za-z0-9 ._-]+?)\s*([0-9][0-9.]+)?$", gen)
                if gm and not product:
                    product, version = gm.group(1).strip(), (gm.group(2) or "")
                    conf = "medium"
            else:
                tech.append(label)
                ver = ""
                if m.lastindex:
                    ver = m.group(1) if (m.group(1) or "")[:1].isdigit() else ""
                # app label is more interesting than 'nginx' for CVE purposes
                if label.lower() not in ("atlassian",):
                    product, version, conf = label, ver, ("medium" if ver else "low")
    if tech:
        info["tech"] = sorted(set(tech))
    return info, (product, version, conf)


# ---------------------------------------------------------------------------
# TLS certificate
# ---------------------------------------------------------------------------
async def tls_info(host: str, port: int, timeout: float) -> dict:
    def _grab():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        import socket
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                proto = ss.version()
        out = {"tls_version": proto}
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID, ExtensionOID
            cert = x509.load_der_x509_certificate(der)
            try:
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                out["subject_cn"] = cn[0].value if cn else ""
            except Exception:
                pass
            try:
                icn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                out["issuer_cn"] = icn[0].value if icn else ""
            except Exception:
                pass
            try:
                ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                from cryptography.x509 import DNSName
                out["sans"] = ext.value.get_values_for_type(DNSName)
            except Exception:
                pass
        except Exception:
            pass
        return out

    try:
        return await asyncio.to_thread(_grab)
    except Exception as e:  # noqa: BLE001
        utils.debug(f"tls {host}:{port}: {type(e).__name__}")
        return {}


# ---------------------------------------------------------------------------
# Merge logic
# ---------------------------------------------------------------------------
_CONF_RANK = {"": 0, "low": 1, "medium": 2, "high": 3}


def _merge_candidate(svc: Service, product: str, version: str,
                     source: str, conf: str) -> None:
    """Adopt product/version if it's more specific than what we have."""
    if not product and not version:
        return
    cur = _CONF_RANK[svc.confidence]
    new = _CONF_RANK[conf or "low"]
    # prefer: having a version > not; then higher confidence
    gain_version = bool(version) and not svc.version
    better_conf = new > cur
    if gain_version or better_conf or not svc.product:
        if product:
            svc.product = product
        if version:
            svc.version = version
        if conf and new >= cur:
            svc.confidence = conf
    if source not in svc.sources:
        svc.sources.append(source)


def _attach_aux(svc: Service, info: dict) -> None:
    """Move any secondary products parsed from HTTP headers onto svc.aux (so
    CVE correlation queries them too) and keep them out of the raw http dict."""
    for pair in info.pop("aux", []):
        if pair not in svc.aux:
            svc.aux.append(pair)


_HTTP_PORTS = {80, 8080, 8000, 8888, 591, 8008, 8081, 3000, 5000, 9000}
_TLS_PORTS = {443, 8443, 9443, 4443}


async def fingerprint_service(cfg: ScanConfig, http, host: str,
                              svc: Service) -> None:
    """Run the probe set appropriate for this port and merge findings.

    Key design point: when a service is under-identified (unknown name / no
    product), we don't trust the port number — we try a banner grab AND an
    HTTP(S) probe regardless, because that's exactly where nmap's -sV gives up
    and a standard port assumption would be wrong.
    """
    name = (svc.name or "").lower()
    under_identified = (not svc.product) or (not svc.version) or (name in ("", "unknown"))

    is_http = ("http" in name and "https" not in name) or svc.port in _HTTP_PORTS
    is_tls = ("https" in name) or ("ssl" in str(svc.tls)) or svc.port in _TLS_PORTS

    # 1) banner grab for non-HTTP (or unknown) services
    if not is_http:
        banner = await banner_grab(host, svc.port, cfg.timeout)
        # IRC greets on connect but hides its version; a VERSION command elicits
        # the identifying numerics. Re-probe when the greeting looks like IRC.
        if banner and ("irc" in banner.lower() or " NOTICE AUTH " in banner
                       or re.search(r"^:[^ ]+ \d{3} ", banner, re.M)):
            richer = await irc_probe(host, svc.port, cfg.timeout)
            if richer and len(richer) > len(banner):
                banner = richer
        if banner:
            svc.banner = banner[:300]
            # an open interactive shell / bindshell = unauthenticated RCE; the
            # worst finding on a host and one nmap usually leaves as 'unknown'.
            if detect_shell(banner):
                svc.name = "shell"
                if not svc.product:
                    svc.product = "Interactive command shell"
                svc.extrainfo = "UNAUTHENTICATED command shell (bindshell/backdoor)"
                svc.confidence = "high"
                if "banner" not in svc.sources:
                    svc.sources.append("banner")
                svc.scripts.append({
                    "id": "bindshell-detect",
                    "output": "open interactive command shell on connect -- "
                              "unauthenticated remote command execution (CRITICAL)"})
            p, v, c = parse_banner(banner)
            _merge_candidate(svc, p, v, "banner", c)
            # if the banner looks like HTTP, flag for an HTTP probe below
            if banner[:5].upper().startswith(("HTTP/", "HTTP ")):
                is_http = True

    # 1b) AJP13 connector (silent binary protocol -> banner grab yields nothing).
    #     Confirm with CPing/CPong on the canonical port or anything nmap tagged
    #     ajp*. Definitive and non-destructive (no AJP request is processed).
    if (not is_http and svc.name != "shell"
            and ("ajp" in name or svc.port == 8009)):
        if await ajp_probe(host, svc.port, cfg.timeout):
            svc.name = "ajp13"
            if not svc.product:
                svc.product = "Apache JServ Protocol (AJP13)"
            svc.confidence = "high"
            if "ajp" not in svc.sources:
                svc.sources.append("ajp")
            svc.scripts.append({
                "id": "ajp13-detect",
                "output": "AJP13 connector confirmed via CPing/CPong. If reachable "
                          "from an untrusted network this exposes the Ghostcat "
                          "attack surface (CVE-2020-1938: file read / JSP source "
                          "disclosure and potential inclusion via AJP). Confirm "
                          "exposure and the Tomcat version separately."})

    # 2) TLS cert
    if is_tls:
        t = await tls_info(host, svc.port, cfg.timeout)
        if t:
            svc.tls.update(t)

    # 3) HTTP fingerprint — on known-web ports, TLS ports, OR any service nmap
    #    couldn't pin down (fall back to probing http then https).
    tried_http = False
    if is_http or is_tls:
        info, (p, v, c) = await http_fingerprint(http, host, svc.port, is_tls)
        tried_http = True
        if info.get("status"):
            _attach_aux(svc, info)
            svc.http.update(info)
            _merge_candidate(svc, p, v, "http", c)
            if not svc.name:
                svc.name = "https" if is_tls else "http"

    if under_identified and not svc.product and not tried_http:
        # last-resort: try HTTP then HTTPS on this port
        for use_tls in (False, True):
            info, (p, v, c) = await http_fingerprint(http, host, svc.port, use_tls)
            if info.get("status"):
                _attach_aux(svc, info)
                svc.http.update(info)
                _merge_candidate(svc, p, v, "http", c)
                if not svc.name:
                    svc.name = "https" if use_tls else "http"
                break


async def run_fingerprint(cfg: ScanConfig, http, host: str,
                          services: list[Service]) -> None:
    """Fingerprint the services nmap under-identified (or all, if fp_all)."""
    from .nmap_engine import needs_fingerprint
    targets = [s for s in services if cfg.fp_all or needs_fingerprint(s)]
    if not targets:
        return
    utils.info(f"fingerprinting {len(targets)} service(s)")
    sem = asyncio.Semaphore(cfg.concurrency)

    async def one(svc: Service):
        async with sem:
            try:
                await fingerprint_service(cfg, http, host, svc)
            except Exception as e:  # noqa: BLE001
                utils.debug(f"fingerprint :{svc.port} err {e}")

    await asyncio.gather(*(one(s) for s in targets))
    improved = sum(1 for s in targets if s.version)
    utils.good(f"fingerprint done ({improved}/{len(targets)} now have a version)")
