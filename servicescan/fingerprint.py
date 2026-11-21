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
import struct

from .config import ScanConfig
from .models import Service
from .nmap_engine import is_coyote_misattrib, _COYOTE_CPE_PRODUCTS
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


# ---------------------------------------------------------------------------
# FTP explicit-TLS (AUTH TLS/SSL, RFC 4217) probe
# ALPACA (CVE-2021-3618) is a TLS cross-protocol attack: it is only meaningful
# when the FTP service actually speaks TLS (explicit AUTH TLS/SSL, or implicit
# FTPS on 990). This strictly read-only probe asks the server whether it offers
# AUTH TLS so CVE refinement can demote ALPACA on plaintext-only FTP (where it
# cannot apply) WITHOUT deleting the finding. It never starts a TLS handshake:
# it reads the 220 greeting, inspects FEAT output, and as a fallback inspects
# the AUTH reply code, then closes.
# ---------------------------------------------------------------------------
_FTP_AUTH_TLS_RX = re.compile(rb"AUTH[ \t]+(?:TLS|SSL)", re.I)


async def ftp_tls_probe(host: str, port: int, timeout: float) -> bool:
    """True if the FTP service offers explicit TLS (AUTH TLS/SSL).

    Read-only: reads the 220 greeting, sends FEAT and scans the reply for an
    AUTH TLS/SSL feature line; if FEAT does not advertise it, sends `AUTH TLS`
    and treats a 234 reply (server ready to negotiate) as support. The TLS
    handshake itself is never begun.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:  # noqa: BLE001
        return False
    try:
        # 220 greeting (consume it so FEAT's reply is read cleanly)
        try:
            await asyncio.wait_for(reader.read(512), timeout=min(3.0, timeout))
        except asyncio.TimeoutError:
            pass
        # compliant servers advertise the capability in FEAT
        writer.write(b"FEAT\r\n")
        await writer.drain()
        feat = b""
        try:
            feat = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        except asyncio.TimeoutError:
            feat = b""
        if _FTP_AUTH_TLS_RX.search(feat):
            return True
        # fallback: ask directly. 234 = "ready to start TLS"; we stop there and
        # never send the ClientHello, so nothing is encrypted or negotiated.
        writer.write(b"AUTH TLS\r\n")
        await writer.drain()
        try:
            resp = await asyncio.wait_for(reader.read(256), timeout=timeout)
        except asyncio.TimeoutError:
            resp = b""
        return resp.lstrip()[:3] == b"234"
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass


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
# distcc (distributed C/C++ compiler daemon)
# distccd (classically TCP 3632) speaks a silent binary token protocol, so a
# banner grab returns nothing and nmap commonly leaves the port 'unknown'. When
# started without an --allow ACL and reachable from an untrusted network the
# daemon compiles -- i.e. executes -- jobs from any client, which is remote
# command execution (CVE-2004-2687).
#
# A distccd only ever emits bytes after it has run a compile job, so the one
# "definitive" reply is also the one we must never trigger: confirming the
# service by its protocol response would mean executing a command on the
# target. Instead we identify it by a strictly read-only behavioural signature
# that runs NOTHING on the host:
#   1. distccd is silent on connect and holds the socket open waiting for a
#      request (a service that greets, or closes at once, is not distccd); and
#   2. given a DIST header carrying an UNSUPPORTED protocol version, distccd
#      reads the DIST token, rejects the version, and closes the connection
#      immediately with no data -- before any job is read or any compiler is
#      forked. (Verified against distccd 2.x: the bad-version path never spawns
#      a compiler.)
# This is a heuristic, not a protocol handshake, so it reports at medium
# confidence; it is gated to the canonical port / nmap's distcc tag so it
# cannot mislabel unrelated silent services elsewhere.
# ---------------------------------------------------------------------------
# A DIST token is a 4-char tag + 8 ASCII-hex chars (a 32-bit value). 0xffffffff
# is not a real distcc protocol version, so the daemon bails at the version
# check and never proceeds to read (let alone run) a job.
_DISTCC_BADVER = b"DISTffffffff"


async def distcc_probe(host: str, port: int, timeout: float) -> bool:
    """True if the port behaves like a distcc daemon (read-only heuristic).

    Confirms the two distccd-specific behaviours (silent-and-open on connect,
    prompt data-less close after a bad-version DIST header) without ever
    submitting a job. No command is supplied to or executed on the target.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:  # noqa: BLE001
        return False
    try:
        # 1) distccd never greets and never closes on connect: it waits for a
        #    request. The only distcc-consistent outcome is a read timeout
        #    (silent, still open). Any bytes (a banner) or an immediate EOF
        #    (closed on connect) rules it out.
        try:
            await asyncio.wait_for(reader.read(16), timeout=min(1.5, timeout))
            return False
        except asyncio.TimeoutError:
            pass
        # 2) a bad-version DIST header -> distccd rejects it and closes with no
        #    data. EOF (b"") = distcc-consistent; a timeout or any bytes is not.
        writer.write(_DISTCC_BADVER)
        await writer.drain()
        try:
            resp = await asyncio.wait_for(reader.read(16), timeout=timeout)
        except asyncio.TimeoutError:
            return False
        return resp == b""
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Unauthenticated-exposure checks (read-only)
# A data store reachable without credentials is a critical finding on its own,
# and one nmap reports only as a plain service. These probes send strictly
# read-only, non-mutating commands and never write or delete anything: Redis
# INFO, memcached version, MongoDB listDatabases. Each returns ("open", version)
# when unauthenticated access works, ("auth", "") when the service is present
# but demands credentials, or None when it is not that service.
# ---------------------------------------------------------------------------
_REDIS_VER = re.compile(rb"redis_version:([0-9][0-9.]+)")
_MEMC_VER = re.compile(rb"VERSION ([0-9][0-9A-Za-z._-]+)")


async def _read_once(host: int, port: int, payload: bytes, timeout: float,
                     nbytes: int = 4096) -> bytes:
    """Open, send payload, read one response, close. b'' on any failure."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:  # noqa: BLE001
        return b""
    data = b""
    try:
        writer.write(payload)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(nbytes), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
    except Exception:  # noqa: BLE001
        data = b""
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass
    return data


async def redis_probe(host: str, port: int, timeout: float):
    """Redis INFO (read-only). ('open', version) / ('auth', '') / None."""
    data = await _read_once(host, port, b"INFO\r\n", timeout)
    if not data:
        return None
    if b"redis_version:" in data:
        m = _REDIS_VER.search(data)
        return ("open", m.group(1).decode() if m else "")
    low = data.lower()
    if data[:1] == b"-" and (b"noauth" in low or b"auth" in low
                             or b"protected mode" in low or b"wrongpass" in low):
        return ("auth", "")        # present, but password / protected mode
    return None


async def memcached_probe(host: str, port: int, timeout: float):
    """memcached version (read-only). ('open', version) / ('auth', '') / None."""
    data = await _read_once(host, port, b"version\r\n", timeout)
    if not data:
        return None
    if data[:8] == b"VERSION ":
        m = _MEMC_VER.search(data)
        return ("open", m.group(1).decode() if m else "")
    if b"ERROR" in data[:32]:       # SASL-enabled instances refuse the text cmd
        return ("auth", "")
    return None


def _mongo_listdb_msg() -> bytes:
    """An OP_MSG for { listDatabases: 1, nameOnly: true, $db: "admin" } -- a
    read-only command that lists database names (and fails with an auth error
    when authorization is enabled)."""
    el = b""
    el += b"\x10" + b"listDatabases\x00" + struct.pack("<i", 1)   # int32 = 1
    el += b"\x08" + b"nameOnly\x00" + b"\x01"                      # bool true
    el += b"\x02" + b"$db\x00" + struct.pack("<i", 6) + b"admin\x00"  # string
    doc = struct.pack("<i", len(el) + 5) + el + b"\x00"           # BSON document
    body = struct.pack("<I", 0) + b"\x00" + doc        # flagBits=0, section 0
    header = struct.pack("<iiii", 16 + len(body), 1, 0, 2013)     # OP_MSG=2013
    return header + body


async def mongodb_probe(host: str, port: int, timeout: float):
    """MongoDB listDatabases (read-only). ('open', '') / ('auth', '') / None."""
    data = await _read_once(host, port, _mongo_listdb_msg(), timeout, nbytes=8192)
    if len(data) < 16:
        return None
    low = data.lower()
    if b"databases" in low:
        return ("open", "")         # listing succeeded without credentials
    if (b"not authorized" in low or b"requires authentication" in low
            or b"unauthorized" in low or b"authentication" in low):
        return ("auth", "")
    return None


# --- HTTP(S)-based stores: Elasticsearch / CouchDB / Docker API / etcd / kubelet
# All read-only GETs (no POST/PUT/DELETE), no redirects followed.
async def _http_get_once(host: str, port: int, path: str, timeout: float,
                         tls: bool = False, extra_headers: dict | None = None,
                         nbytes: int = 16384):
    """Raw HTTP/1.0 GET. Returns (status:int, headers:dict, body:bytes) or None.
    Strictly read-only; follows no redirects; TLS cert never verified.
    extra_headers adds request headers (e.g. Authorization for a default-cred
    test)."""
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
    except Exception:  # noqa: BLE001
        return None
    raw = b""
    try:
        extra = "".join(f"{k}: {v}\r\n"
                        for k, v in (extra_headers or {}).items())
        req = (f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
               f"User-Agent: servicescan\r\nAccept: */*\r\n"
               f"{extra}Connection: close\r\n\r\n")
        writer.write(req.encode())
        await writer.drain()
        try:
            while len(raw) < nbytes:
                chunk = await asyncio.wait_for(reader.read(nbytes), timeout=timeout)
                if not chunk:
                    break
                raw += chunk
        except asyncio.TimeoutError:
            pass
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass
    if not raw.startswith(b"HTTP/"):
        return None
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    try:
        status = int(lines[0].split(b" ")[1])
    except (IndexError, ValueError):
        return None
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        if k:
            headers[k.strip().lower().decode("latin-1", "replace")] = \
                v.strip().decode("latin-1", "replace")
    return status, headers, body


def _json_ver(body: bytes, key: str) -> str:
    m = re.search(rb'"' + re.escape(key.encode()) + rb'"\s*:\s*"([0-9][0-9.]+)',
                  body)
    return m.group(1).decode() if m else ""


async def elasticsearch_probe(host: str, port: int, timeout: float, tls: bool):
    """Elasticsearch root (read-only). ('open', version) / ('auth', '') / None."""
    r = await _http_get_once(host, port, "/", timeout, tls)
    if not r:
        return None
    status, _, body = r
    low = body.lower()
    if status == 200 and (b"you know, for search" in low
                          or b'"cluster_name"' in low or b"lucene_version" in low):
        return ("open", _json_ver(body, "number"))
    if status in (401, 403):
        return ("auth", "")
    return None


async def couchdb_probe(host: str, port: int, timeout: float, tls: bool):
    """CouchDB welcome + /_all_dbs (read-only). ('open', v)/('auth','')/None."""
    r = await _http_get_once(host, port, "/", timeout, tls)
    if not r:
        return None
    status, _, body = r
    if b'"couchdb"' not in body.lower() or b"welcome" not in body.lower():
        if status in (401, 403):
            return ("auth", "")
        return None
    ver = _json_ver(body, "version")
    r2 = await _http_get_once(host, port, "/_all_dbs", timeout, tls)
    if r2 and r2[0] == 200 and r2[2].lstrip().startswith(b"["):
        return ("open", ver)
    return ("auth", "")        # CouchDB confirmed, but listing refused


async def docker_api_probe(host: str, port: int, timeout: float, tls: bool):
    """Docker Engine API /version (read-only). ('open', v)/('auth','')/None."""
    r = await _http_get_once(host, port, "/version", timeout, tls)
    if not r:
        return None
    status, _, body = r
    if status == 200 and b'"ApiVersion"' in body and b'"GoVersion"' in body:
        return ("open", _json_ver(body, "Version"))
    if status in (401, 403):
        return ("auth", "")
    return None


async def etcd_probe(host: str, port: int, timeout: float, tls: bool):
    """etcd /version + /v2/keys read (read-only). ('open', v)/('auth','')/None.
    Only confirms exposure when the v2 keyspace is readable unauthenticated;
    a v3-only (gRPC) node is left to nmap rather than guessed over HTTP."""
    r = await _http_get_once(host, port, "/version", timeout, tls)
    if not r or b'"etcdserver"' not in r[2]:
        return None
    ver = _json_ver(r[2], "etcdserver")
    r2 = await _http_get_once(host, port, "/v2/keys/?recursive=false", timeout, tls)
    if not r2:
        return None
    status, _, body = r2
    if status == 200 and b'"action"' in body:
        return ("open", ver)
    if status in (401, 403):
        return ("auth", "")
    return None            # v2 disabled (404): cannot confirm over HTTP -> no claim


async def kubelet_probe(host: str, port: int, timeout: float, tls: bool):
    """kubelet /pods (read-only). ('open','') when anonymous auth is enabled
    (PodList returned) / ('auth','') when refused / None."""
    r = await _http_get_once(host, port, "/pods", timeout, tls)
    if not r:
        return None
    status, _, body = r
    if status == 200 and b'"kind"' in body and b'"PodList"' in body:
        return ("open", "")
    if status in (401, 403):
        return ("auth", "")
    return None


_REDIS_PORTS = {6379, 6380}
_MEMCACHED_PORTS = {11211}
_MONGO_PORTS = {27017, 27018, 27019}
_ES_PORTS = {9200, 9201}
_COUCHDB_PORTS = {5984, 6984}
_DOCKER_PORTS = {2375, 2376}
_ETCD_PORTS = {2379, 4001}
_KUBELET_PORTS = {10250, 10255}
_RTSP_PORTS = {554, 8554, 7447, 10554, 1554, 555}
_RTSPS_PORTS = {322}                             # RTSP over TLS (RTSPS, IANA 322)
# ports that always speak TLS (the plaintext peer, when one exists, is elsewhere)
_TLS_EXPOSURE_PORTS = {2376, 6984, 10250}


# ---------------------------------------------------------------------------
# RTSP (cameras / NVRs). RTSP is a text protocol like HTTP; a read-only OPTIONS
# names the server and lists methods, and an unauthenticated DESCRIBE tells us
# whether the stream is open (200 + SDP) or gated (401 + WWW-Authenticate). On a
# gated stream we optionally try a tiny set of factory-default credentials
# (Basic and Digest) -- the one active step, kept to common camera defaults.
# Nothing is ever PLAYed or recorded; DESCRIBE only fetches the SDP metadata.
# ---------------------------------------------------------------------------
_RTSP_DESCRIBE_PATHS = [
    "/",                                        # base (also the auth-scheme probe)
    "/Streaming/Channels/101",                  # Hikvision
    "/cam/realmonitor?channel=1&subtype=0",     # Dahua
    "/axis-media/media.amp",                    # Axis
    "/h264Preview_01_main",                     # Reolink
    "/videoMain",                               # Foscam
    "/profile1",                                # Hanwha / Samsung WiseNet
    "/live.sdp", "/live/ch0", "/live/main",     # generic / cheap-OEM
    "/11", "/stream1", "/video1", "/ch01.264",  # generic / DVR
]
# factory defaults only; tiny list to avoid lockouts / noise ("" = blank password)
_RTSP_DEFAULT_CREDS = [("admin", "admin"), ("admin", ""), ("root", "root"),
                       ("admin", "12345"), ("admin", "password"), ("root", "")]
_RTSP_STATUS_RX = re.compile(r"RTSP/\d\.\d\s+(\d+)")


def _parse_rtsp(data: bytes) -> dict | None:
    """Parse an RTSP response. Returns {code, headers(lower-keyed), body} or
    None when the reply is not RTSP (so we never mislabel a non-RTSP port)."""
    text = data.decode("latin-1", "replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    m = _RTSP_STATUS_RX.match(lines[0] if lines else "")
    if not m:
        return None
    hdrs: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return {"code": int(m.group(1)), "headers": hdrs, "body": body}


async def _rtsp_request(host: str, port: int, timeout: float, method: str,
                        path: str, headers: dict | None = None,
                        tls: bool = False) -> dict | None:
    """Send one RTSP request on a fresh connection (CSeq 1) and parse the reply.
    Read-only: only OPTIONS / DESCRIBE are ever issued by callers here. With
    tls=True the connection is TLS-wrapped (RTSPS); the RTSP layer is identical."""
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
    except Exception:  # noqa: BLE001
        return None
    url = f"rtsp://{host}:{port}{path}"
    lines = [f"{method} {url} RTSP/1.0", "CSeq: 1", "User-Agent: servicescan"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    req = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")
    data = b""
    try:
        writer.write(req)
        await writer.drain()
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            if not chunk:
                break
            data += chunk
        # pull the SDP body (DESCRIBE 200) up to its Content-Length
        head, sep, rest = data.partition(b"\r\n\r\n")
        cl = re.search(rb"Content-Length:\s*(\d+)", head, re.I)
        if sep and cl:
            need = min(int(cl.group(1)), 131072)
            while len(rest) < need:
                chunk = await asyncio.wait_for(reader.read(2048), timeout=timeout)
                if not chunk:
                    break
                rest += chunk
            data = head + sep + rest
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass
    return _parse_rtsp(data) if data else None


def _parse_www_auth(wa: str) -> tuple[str, str, str, str]:
    """(scheme, realm, nonce, qop) from a WWW-Authenticate header."""
    low = wa.lower()
    scheme = "Digest" if "digest" in low else ("Basic" if "basic" in low else "")
    def grab(key):
        m = re.search(key + r'\s*=\s*"?([^",]*)"?', wa, re.I)
        return m.group(1) if m else ""
    return scheme, grab("realm"), grab("nonce"), grab("qop")


def _rtsp_auth_header(scheme: str, realm: str, nonce: str, qop: str,
                      user: str, pw: str, method: str, uri: str) -> str:
    """Build an Authorization header for one credential (Basic or Digest)."""
    if scheme == "Basic":
        import base64
        return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    if scheme == "Digest" and realm and nonce:
        import hashlib
        h = lambda s: hashlib.md5(s.encode()).hexdigest()  # noqa: E731
        ha1 = h(f"{user}:{realm}:{pw}")
        ha2 = h(f"{method}:{uri}")
        if qop:
            nc, cnonce = "00000001", "0a4f113b"
            resp = h(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
            return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
                    f'uri="{uri}", response="{resp}", qop={qop}, nc={nc}, '
                    f'cnonce="{cnonce}"')
        resp = h(f"{ha1}:{nonce}:{ha2}")
        return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
                f'uri="{uri}", response="{resp}"')
    return ""


async def rtsp_probe(host: str, port: int, timeout: float,
                     tls: bool = False) -> dict | None:
    """Read-only RTSP recon. Returns None if the port is not RTSP, else a dict:
    {server, public, unauth(bool), unauth_path, auth(scheme), realm, nonce, qop,
    auth_path}. OPTIONS gives presence+banner; an unauthenticated DESCRIBE over
    common stream paths detects an open stream (200+SDP) or the auth scheme (401).
    tls=True probes RTSPS (RTSP over TLS, e.g. port 322)."""
    opt = await _rtsp_request(host, port, timeout, "OPTIONS", "/", tls=tls)
    if opt is None:
        return None                              # not RTSP (or no response)
    info = {"server": opt["headers"].get("server", ""),
            "public": opt["headers"].get("public", ""),
            "unauth": False, "unauth_path": "",
            "auth": "", "realm": "", "nonce": "", "qop": "", "auth_path": "/"}
    for path in _RTSP_DESCRIBE_PATHS:
        r = await _rtsp_request(host, port, timeout, "DESCRIBE", path,
                                {"Accept": "application/sdp"}, tls=tls)
        if r is None:
            continue
        ctype = r["headers"].get("content-type", "").lower()
        if r["code"] == 200 and ("sdp" in ctype or r["body"].startswith("v=")):
            info["unauth"] = True
            info["unauth_path"] = path
            return info                          # open stream found -> stop
        if r["code"] == 401 and not info["auth"]:
            sc, realm, nonce, qop = _parse_www_auth(
                r["headers"].get("www-authenticate", ""))
            info["auth"], info["realm"] = sc, realm
            info["nonce"], info["qop"] = nonce, qop
            info["auth_path"] = path
    return info


async def rtsp_try_default_creds(host: str, port: int, timeout: float,
                                 info: dict, tls: bool = False) -> str | None:
    """Try the tiny factory-default credential list against a gated stream via
    DESCRIBE. Returns 'user:pass' on the first 200, else None. Active step."""
    if not info.get("auth"):
        return None
    path = info.get("auth_path") or "/"
    uri = f"rtsp://{host}:{port}{path}"
    for user, pw in _RTSP_DEFAULT_CREDS:
        hdr = _rtsp_auth_header(info["auth"], info["realm"], info["nonce"],
                                info["qop"], user, pw, "DESCRIBE", uri)
        if not hdr:
            continue
        r = await _rtsp_request(host, port, timeout, "DESCRIBE", path,
                                {"Accept": "application/sdp",
                                 "Authorization": hdr}, tls=tls)
        if r and r["code"] == 200:
            return f"{user}:{pw or '<blank>'}"
    return None


# ---------------------------------------------------------------------------
# ONVIF (IP cameras / NVRs). SOAP over HTTP at /onvif/device_service. ONVIF's
# GetSystemDateAndTime is unauthenticated BY SPEC (clients need the device clock
# to build a WS-UsernameToken), so it is a clean read-only presence+time probe.
# GetDeviceInformation needs auth: unauthenticated it returns the device make/
# model (misconfig) or a SOAP Fault (gated). On a gated device we optionally try
# the same tiny default-credential list via a WS-UsernameToken PasswordDigest.
# ---------------------------------------------------------------------------
_ONVIF_PATH = "/onvif/device_service"
_ONVIF_PORTS = {8000, 8899, 2020, 8081, 10080}   # common ONVIF-only HTTP ports
_ONVIF_DEV_NS = "http://www.onvif.org/ver10/device/wsdl"
_ONVIF_MEDIA_NS = "http://www.onvif.org/ver10/media/wsdl"
_ONVIF_SCHEMA_NS = "http://www.onvif.org/ver10/schema"
_ONVIF_URI_RX = re.compile(r"<(?:\w+:)?Uri>\s*([^<][^<]*?)\s*</(?:\w+:)?Uri>", re.I)
_ONVIF_DEVINFO_RX = {
    "manufacturer": re.compile(r"<[^>]*Manufacturer>([^<]+)<", re.I),
    "model": re.compile(r"<[^>]*Model>([^<]+)<", re.I),
    "firmware": re.compile(r"<[^>]*FirmwareVersion>([^<]+)<", re.I),
    "serial": re.compile(r"<[^>]*SerialNumber>([^<]+)<", re.I),
}
# ONVIF orders UTCDateTime as Time(Hour,Minute,Second) THEN Date(Year,Month,Day),
# so parse each field independently inside the block rather than assuming order.
_ONVIF_UTC_BLOCK = re.compile(r"UTCDateTime[^>]*>(.*?)</[^>]*UTCDateTime>",
                              re.I | re.S)


def _onvif_utc_created(body: str) -> str:
    mb = _ONVIF_UTC_BLOCK.search(body)
    if not mb:
        return ""
    blk = mb.group(1)
    def f(name):
        m = re.search(rf"<[^>]*{name}>\s*(\d+)\s*<", blk, re.I)
        return int(m.group(1)) if m else None
    y, mo, d, hh, mm, ss = (f("Year"), f("Month"), f("Day"),
                            f("Hour"), f("Minute"), f("Second"))
    if None in (y, mo, d, hh, mm, ss):
        return ""
    return f"{y:04d}-{mo:02d}-{d:02d}T{hh:02d}:{mm:02d}:{ss:02d}Z"


async def _http_post_once(host: str, port: int, path: str, body: bytes,
                          timeout: float, tls: bool = False,
                          content_type: str = "application/soap+xml; charset=utf-8",
                          nbytes: int = 32768):
    """Raw HTTP/1.0 POST. Returns (status, headers, body:bytes) or None.
    Read-only in effect (ONVIF GET-style SOAP calls); no redirects, no TLS verify."""
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
    except Exception:  # noqa: BLE001
        return None
    raw = b""
    try:
        req = (f"POST {path} HTTP/1.0\r\nHost: {host}\r\n"
               f"User-Agent: servicescan\r\nContent-Type: {content_type}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        writer.write(req + body)
        await writer.drain()
        try:
            while len(raw) < nbytes:
                chunk = await asyncio.wait_for(reader.read(nbytes), timeout=timeout)
                if not chunk:
                    break
                raw += chunk
        except asyncio.TimeoutError:
            pass
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass
    if not raw.startswith(b"HTTP/"):
        return None
    head, _, rbody = raw.partition(b"\r\n\r\n")
    try:
        status = int(head.split(b"\r\n")[0].split(b" ")[1])
    except (IndexError, ValueError):
        return None
    return status, {}, rbody


def _onvif_envelope(body_inner: str, header: str = "") -> bytes:
    hdr = f"<s:Header>{header}</s:Header>" if header else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        f'{hdr}<s:Body>{body_inner}</s:Body></s:Envelope>'
    ).encode()


def _onvif_ws_security(user: str, pw: str, created: str) -> str:
    """WS-UsernameToken with PasswordDigest = Base64(SHA1(nonce+created+pass))."""
    import base64
    import hashlib
    import os as _os
    nonce = _os.urandom(16)
    digest = base64.b64encode(
        hashlib.sha1(nonce + created.encode() + pw.encode()).digest()).decode()
    wsse = ("http://docs.oasis-open.org/wss/2004/01/"
            "oasis-200401-wss-wssecurity-secext-1.0.xsd")
    wsu = ("http://docs.oasis-open.org/wss/2004/01/"
           "oasis-200401-wss-wssecurity-utility-1.0.xsd")
    pt = ("http://docs.oasis-open.org/wss/2004/01/"
          "oasis-200401-wss-username-token-profile-1.0#PasswordDigest")
    et = ("http://docs.oasis-open.org/wss/2004/01/"
          "oasis-200401-wss-soap-message-security-1.0#Base64Binary")
    return (
        f'<Security s:mustUnderstand="1" xmlns="{wsse}"><UsernameToken>'
        f'<Username>{user}</Username>'
        f'<Password Type="{pt}">{digest}</Password>'
        f'<Nonce EncodingType="{et}">{base64.b64encode(nonce).decode()}</Nonce>'
        f'<Created xmlns="{wsu}">{created}</Created>'
        f'</UsernameToken></Security>'
    )


def _parse_onvif_devinfo(body: bytes) -> dict:
    text = body.decode("latin-1", "replace")
    out = {}
    for key, rx in _ONVIF_DEVINFO_RX.items():
        m = rx.search(text)
        if m:
            out[key] = m.group(1).strip()
    return out


async def onvif_probe(host: str, port: int, timeout: float,
                      tls: bool = False) -> dict | None:
    """Read-only ONVIF recon. None if not ONVIF, else {created, unauth(bool),
    device{...}, auth(bool)}. GetSystemDateAndTime confirms ONVIF + gives the
    device clock; an unauthenticated GetDeviceInformation reveals make/model
    (misconfig) or faults (gated)."""
    dt = await _http_post_once(host, port, _ONVIF_PATH,
        _onvif_envelope(f'<GetSystemDateAndTime xmlns="{_ONVIF_DEV_NS}"/>'),
        timeout, tls)
    if dt is None:
        return None
    body = dt[2].decode("latin-1", "replace")
    if "SystemDateAndTime" not in body and "onvif.org/ver10/device" not in body:
        return None                              # not an ONVIF device_service
    created = _onvif_utc_created(body)
    info = {"created": created, "unauth": False, "device": {}, "auth": False}
    gi = await _http_post_once(host, port, _ONVIF_PATH,
        _onvif_envelope(f'<GetDeviceInformation xmlns="{_ONVIF_DEV_NS}"/>'),
        timeout, tls)
    if gi is not None:
        gbody = gi[2]
        dev = _parse_onvif_devinfo(gbody)
        if gi[0] == 200 and dev:
            info["unauth"], info["device"] = True, dev
        elif b"Fault" in gbody or gi[0] in (400, 401):
            info["auth"] = True
    return info


async def onvif_try_default_creds(host: str, port: int, timeout: float,
                                  info: dict, tls: bool = False):
    """Try the default-credential list with a WS-UsernameToken GetDeviceInformation.
    Returns (user, pw, device_dict) on the first success, else None. Active step."""
    created = info.get("created") or _utcnow_iso()
    for user, pw in _RTSP_DEFAULT_CREDS:
        env = _onvif_envelope(
            f'<GetDeviceInformation xmlns="{_ONVIF_DEV_NS}"/>',
            _onvif_ws_security(user, pw, created))
        r = await _http_post_once(host, port, _ONVIF_PATH, env, timeout, tls)
        if r and r[0] == 200:
            dev = _parse_onvif_devinfo(r[2])
            if dev:
                return user, pw, dev
    return None


# ONVIF read-only enumeration, run once access is confirmed (unauth misconfig or
# a working default credential). GetUsers lists the device's accounts and their
# privilege level; GetProfiles lists the media profiles (stream name, resolution,
# codec). Both are "Get" calls -- no configuration is changed. `mksec` is a
# zero-arg factory returning a fresh WS-UsernameToken header (a new nonce per
# request, so replay protection never rejects us) or None for the unauth path.
def _parse_onvif_users(body: bytes) -> list[dict]:
    text = body.decode("latin-1", "replace")
    out = []
    for blk in re.findall(r"<(?:\w+:)?User>(.*?)</(?:\w+:)?User>",
                          text, re.I | re.S):
        u = re.search(r"<(?:\w+:)?Username>([^<]+)<", blk, re.I)
        lvl = re.search(r"<(?:\w+:)?UserLevel>([^<]+)<", blk, re.I)
        if u:
            out.append({"name": u.group(1).strip(),
                        "level": lvl.group(1).strip() if lvl else ""})
    return out


def _parse_onvif_profiles(body: bytes) -> list[dict]:
    text = body.decode("latin-1", "replace")
    out = []
    for m in re.finditer(r"<(?:\w+:)?Profiles\b([^>]*)>(.*?)</(?:\w+:)?Profiles>",
                         text, re.I | re.S):
        attrs, blk = m.group(1), m.group(2)
        tok = re.search(r'token\s*=\s*"([^"]+)"', attrs, re.I)
        name = re.search(r"<(?:\w+:)?Name>([^<]+)<", blk, re.I)
        w = re.search(r"<(?:\w+:)?Width>\s*(\d+)\s*<", blk, re.I)
        h = re.search(r"<(?:\w+:)?Height>\s*(\d+)\s*<", blk, re.I)
        enc = re.search(r"<(?:\w+:)?Encoding>([^<]+)<", blk, re.I)
        prof = {"token": tok.group(1).strip() if tok else "",
                "name": name.group(1).strip() if name else ""}
        if w and h:
            prof["resolution"] = f"{w.group(1)}x{h.group(1)}"
        if enc:
            prof["encoding"] = enc.group(1).strip()
        out.append(prof)
    return out


def _onvif_first_uri(body: bytes) -> str:
    m = _ONVIF_URI_RX.search(body.decode("latin-1", "replace"))
    return m.group(1).strip() if m else ""


def _parse_xaddr(xaddr: str, default_port: int, default_tls: bool):
    """(path, port, tls) from a service XAddr URL. We keep the scanned host and
    only adopt the XAddr's path/port/scheme, so enumeration never pivots to a
    LAN IP the device advertised. Falls back to the device_service endpoint."""
    m = re.match(r"(https?)://[^/:]+(?::(\d+))?(/.*)?$", xaddr, re.I)
    if not m:
        return _ONVIF_PATH, default_port, default_tls
    tls = m.group(1).lower() == "https"
    port = int(m.group(2)) if m.group(2) else (443 if tls else 80)
    return (m.group(3) or _ONVIF_PATH), port, tls


async def onvif_get_users(host: str, port: int, timeout: float,
                          tls: bool = False, mksec=None) -> list[dict]:
    sec = mksec() if mksec else ""
    r = await _http_post_once(host, port, _ONVIF_PATH,
        _onvif_envelope(f'<GetUsers xmlns="{_ONVIF_DEV_NS}"/>', sec), timeout, tls)
    return _parse_onvif_users(r[2]) if r and r[0] == 200 else []


async def _onvif_media_endpoint(host: str, port: int, timeout: float,
                                tls: bool, mksec=None):
    """Discover the media-service endpoint via GetServices; fall back to the
    device_service endpoint when it is absent."""
    sec = mksec() if mksec else ""
    r = await _http_post_once(host, port, _ONVIF_PATH,
        _onvif_envelope(
            f'<GetServices xmlns="{_ONVIF_DEV_NS}">'
            f'<IncludeCapability>false</IncludeCapability></GetServices>', sec),
        timeout, tls)
    if r and r[0] == 200:
        text = r[2].decode("latin-1", "replace")
        for blk in re.findall(r"<(?:\w+:)?Service>(.*?)</(?:\w+:)?Service>",
                              text, re.I | re.S):
            if "ver10/media/wsdl" in blk:
                xa = re.search(r"<(?:\w+:)?XAddr>([^<]+)<", blk, re.I)
                if xa:
                    return _parse_xaddr(xa.group(1).strip(), port, tls)
    return _ONVIF_PATH, port, tls


async def onvif_get_media(host: str, port: int, timeout: float,
                          tls: bool = False, mksec=None,
                          max_profiles: int = 3) -> list[dict]:
    """GetProfiles + per-profile GetStreamUri/GetSnapshotUri (read-only). The
    stream/snapshot URIs are the exact media endpoints the device will serve and
    frequently embed the stream credentials, so they are high-value on an exposed
    camera. All GetProfiles/GetStreamUri/GetSnapshotUri calls are pinned to the
    media endpoint that actually answered (discovered one, else device_service)."""
    cand = await _onvif_media_endpoint(host, port, timeout, tls, mksec)
    dev_ep = (_ONVIF_PATH, port, tls)
    endpoints = [cand] if cand == dev_ep else [cand, dev_ep]

    async def media_post(inner, ep):
        return await _http_post_once(host, ep[1], ep[0],
            _onvif_envelope(inner, mksec() if mksec else ""), timeout, ep[2])

    body, won = None, None
    for ep in endpoints:
        r = await media_post(f'<GetProfiles xmlns="{_ONVIF_MEDIA_NS}"/>', ep)
        if r and r[0] == 200:
            body, won = r[2], ep
            break
    if not body:
        return []
    profiles = _parse_onvif_profiles(body)
    for prof in profiles[:max_profiles]:
        tok = prof.get("token")
        if not tok:
            continue
        su = (f'<GetStreamUri xmlns="{_ONVIF_MEDIA_NS}"><StreamSetup>'
              f'<Stream xmlns="{_ONVIF_SCHEMA_NS}">RTP-Unicast</Stream>'
              f'<Transport xmlns="{_ONVIF_SCHEMA_NS}"><Protocol>RTSP</Protocol>'
              f'</Transport></StreamSetup><ProfileToken>{tok}</ProfileToken>'
              f'</GetStreamUri>')
        r = await media_post(su, won)
        if r and r[0] == 200:
            uri = _onvif_first_uri(r[2])
            if uri:
                prof["stream_uri"] = uri
        sn = (f'<GetSnapshotUri xmlns="{_ONVIF_MEDIA_NS}">'
              f'<ProfileToken>{tok}</ProfileToken></GetSnapshotUri>')
        r = await media_post(sn, won)
        if r and r[0] == 200:
            uri = _onvif_first_uri(r[2])
            if uri:
                prof["snapshot_uri"] = uri
    return profiles


async def _onvif_enum_scripts(svc, host: str, port: int, timeout: float,
                              tls: bool, mksec) -> None:
    """Append onvif-users / onvif-media-profiles info scripts when the read-only
    GetUsers / GetProfiles calls return data (best effort; silent on failure)."""
    users = await onvif_get_users(host, port, timeout, tls, mksec)
    if users:
        svc.scripts.append({"id": "onvif-users", "output":
            "ONVIF accounts exposed (GetUsers): " + ", ".join(
                u["name"] + (f" [{u['level']}]" if u["level"] else "")
                for u in users) + ". Enumerated user names narrow a credential "
            "attack and confirm which accounts hold admin rights."})
    profiles = await onvif_get_media(host, port, timeout, tls, mksec)
    if profiles:
        def fmt(p):
            bits = [p.get("name") or p.get("token") or "?"]
            if p.get("resolution"):
                bits.append(p["resolution"])
            if p.get("encoding"):
                bits.append(p["encoding"])
            line = " ".join(bits)
            if p.get("stream_uri"):
                line += f" stream={p['stream_uri']}"
            if p.get("snapshot_uri"):
                line += f" snapshot={p['snapshot_uri']}"
            return line
        svc.scripts.append({"id": "onvif-media-profiles", "output":
            "ONVIF media profiles (GetProfiles/GetStreamUri/GetSnapshotUri): " +
            "; ".join(fmt(p) for p in profiles) + ". Each profile maps to a live "
            "stream/snapshot the camera serves; the returned URIs often embed the "
            "stream credentials in clear."})


def _utcnow_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Unauthenticated JPEG snapshot. Most IP cameras expose a still-frame URL over
# HTTP; when it is reachable without credentials, a single GET returns a JPEG of
# the live view -- a direct confirmation that the feed is viewable unauth. Gated
# to a camera signal (vendor banner / ONVIF present / camera port) so we never
# spray these paths across unrelated web servers. Read-only GET; stops on the
# first JPEG.
# ---------------------------------------------------------------------------
_CAMERA_PORTS = _RTSP_PORTS | _RTSPS_PORTS | _ONVIF_PORTS
_CAMERA_VENDOR_RX = re.compile(
    r"hikvision|dahua|axis|reolink|hanwha|wisenet|foscam|dlink|d-link|vivotek|"
    r"amcrest|uniview|geovision|mobotix|bosch\s*(security|ip)|ubiquiti|unifi.?video|"
    r"onvif|ip\s*camera|ipcam|netcam|network\s*camera|nvr|dvr|web\s*service",
    re.I)
_CAMERA_SNAPSHOT_PATHS = [
    "/snapshot.jpg", "/onvif-http/snapshot", "/onvifsnapshot/media_service/snapshot",
    "/axis-cgi/jpg/image.cgi", "/cgi-bin/snapshot.cgi",
    "/ISAPI/Streaming/channels/101/picture",         # Hikvision
    "/cgi-bin/api.cgi?cmd=Snap&channel=0",            # Reolink
    "/tmpfs/auto.jpg", "/image/jpeg.cgi", "/jpg/image.jpg",
]


def _looks_like_camera(svc) -> bool:
    """A camera signal on this service: vendor string in product/banner/server,
    a camera-ish service name, or a canonical camera port."""
    hay = " ".join((svc.product or "", svc.name or "", svc.banner or "",
                    (svc.http or {}).get("server", ""),
                    (svc.http or {}).get("title", ""))).lower()
    return bool(_CAMERA_VENDOR_RX.search(hay)) or svc.port in _CAMERA_PORTS


async def camera_snapshot_probe(host: str, port: int, timeout: float,
                                tls: bool = False) -> str | None:
    """GET the common snapshot paths; return the first that answers 200 with a
    JPEG (magic FF D8 FF, or an image/jpeg content-type). Read-only."""
    for path in _CAMERA_SNAPSHOT_PATHS:
        r = await _http_get_once(host, port, path, timeout, tls)
        if not r or r[0] != 200:
            continue
        status, headers, body = r
        ctype = headers.get("content-type", "").lower()
        if body[:3] == b"\xff\xd8\xff" or "image/jpeg" in ctype:
            return path
    return None


# ---------------------------------------------------------------------------
# Vendor camera CGI: the HTTP management API Hikvision/Dahua/Axis cameras expose
# BESIDE RTSP/ONVIF. An unauthenticated GET that returns device info is a
# misconfiguration (e.g. the CVE-2017-7921 ISAPI class); a 401 is probed with a
# tiny default-credential list over HTTP Basic/Digest (reusing the RTSP auth
# builder with method GET). The cred-spray is self-limiting: a vendor path a
# device doesn't implement 404s, so defaults are only tried against the one API
# the device actually speaks. Read-only GETs; gated to a camera signal.
# ---------------------------------------------------------------------------
# camera HTTP defaults = the RTSP set + a couple of vendor-specific ones
_CAM_HTTP_CREDS = _RTSP_DEFAULT_CREDS + [("admin", "12345"), ("root", "pass")]
_VENDOR_CGI = [
    {"vendor": "Hikvision", "path": "/ISAPI/System/deviceInfo",
     "ok": re.compile(r"<DeviceInfo|<deviceName|<firmwareVersion", re.I),
     "model": re.compile(r"<model>([^<]+)<", re.I),
     "fw": re.compile(r"<firmwareVersion>([^<]+)<", re.I)},
    {"vendor": "Dahua", "path": "/cgi-bin/magicBox.cgi?action=getSystemInfo",
     "ok": re.compile(r"deviceType=|serialNumber=|hardwareVersion=", re.I),
     "model": re.compile(r"deviceType=([^\r\n]+)", re.I),
     "fw": re.compile(r"(?:software|firmware)Version=([^\r\n]+)", re.I)},
    {"vendor": "Axis", "path": "/axis-cgi/param.cgi?action=list&group=Brand",
     "ok": re.compile(r"root\.Brand|Brand\.Prod", re.I),
     "model": re.compile(r"Brand\.ProdNbr=([^\r\n]+)", re.I),
     "fw": re.compile(r"Properties\.Firmware\.Version=([^\r\n]+)", re.I)},
]


def _grab(rx, text: str) -> str:
    m = rx.search(text)
    return m.group(1).strip() if m else ""


async def vendor_cgi_probe(host: str, port: int, timeout: float,
                           tls: bool, try_creds: bool) -> list[dict]:
    """Probe vendor camera CGIs. Returns a list of findings, each
    {vendor, path, creds(None=unauth), model, fw}. Read-only."""
    out = []
    for v in _VENDOR_CGI:
        path = v["path"]
        r = await _http_get_once(host, port, path, timeout, tls)
        if r is None:
            continue
        status, headers, body = r
        text = body.decode("latin-1", "replace")
        if status == 200 and v["ok"].search(text):
            out.append({"vendor": v["vendor"], "path": path, "creds": None,
                        "model": _grab(v["model"], text),
                        "fw": _grab(v["fw"], text)})
            continue
        if status == 401 and try_creds:
            sc, realm, nonce, qop = _parse_www_auth(
                headers.get("www-authenticate", ""))
            for user, pw in _CAM_HTTP_CREDS:
                hdr = _rtsp_auth_header(sc, realm, nonce, qop, user, pw,
                                        "GET", path)
                if not hdr:
                    continue
                r2 = await _http_get_once(host, port, path, timeout, tls,
                                          {"Authorization": hdr})
                if r2 and r2[0] == 200:
                    t2 = r2[2].decode("latin-1", "replace")
                    if v["ok"].search(t2):
                        out.append({"vendor": v["vendor"], "path": path,
                                    "creds": f"{user}:{pw or '<blank>'}",
                                    "model": _grab(v["model"], t2),
                                    "fw": _grab(v["fw"], t2)})
                        break
    return out


# ---------------------------------------------------------------------------
# WS-Discovery (ONVIF device discovery, UDP 3702). A unicast Probe for the ONVIF
# NetworkVideoTransmitter type makes a camera/NVR answer with a ProbeMatch that
# names its Types, Scopes (onvif:// name / hardware / location) and the XAddrs of
# its device_service -- no authentication. Run once per host (active recon, one
# datagram); unicast only, so it never leaves the scanned host.
# ---------------------------------------------------------------------------
_WSD_PORTS = {3702}


def _parse_wsd(text: str) -> dict:
    def grab(tag):
        m = re.search(rf"<(?:\w+:)?{tag}>(.*?)</(?:\w+:)?{tag}>", text, re.I | re.S)
        return " ".join(m.group(1).split()) if m else ""
    return {"types": grab("Types"), "scopes": grab("Scopes"),
            "xaddrs": grab("XAddrs")}


async def wsdiscovery_probe(host: str, port: int, timeout: float) -> dict | None:
    """Unicast WS-Discovery Probe. Returns {types, scopes, xaddrs} on a
    ProbeMatch, else None."""
    import uuid
    probe = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        f'<e:Header><w:MessageID>urn:uuid:{uuid.uuid4()}</w:MessageID>'
        '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
        '</e:Header><e:Body><d:Probe>'
        '<d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>'
        '</e:Body></e:Envelope>').encode()
    loop = asyncio.get_event_loop()
    got = loop.create_future()

    class _P(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            if not got.done():
                got.set_result(data)

        def error_received(self, exc):  # noqa: ARG002
            pass

    try:
        transport, _ = await asyncio.wait_for(
            loop.create_datagram_endpoint(_P, remote_addr=(host, port)),
            timeout=timeout)
    except Exception:  # noqa: BLE001
        return None
    try:
        transport.sendto(probe)
        try:
            data = await asyncio.wait_for(got, timeout=timeout)
        except asyncio.TimeoutError:
            return None
    finally:
        transport.close()
    text = data.decode("latin-1", "replace")
    if "ProbeMatch" not in text:
        return None
    return _parse_wsd(text)


# script ids that mark a confirmed unauthenticated/anonymous exposure (critical)
EXPOSURE_ALERT_IDS = {"redis-unauth", "memcached-unauth", "mongodb-unauth",
                      "elasticsearch-unauth", "couchdb-unauth",
                      "docker-api-unauth", "etcd-unauth", "kubelet-anon",
                      "rtsp-unauth", "rtsp-default-creds",
                      "onvif-unauth", "onvif-default-creds",
                      "camera-snapshot-unauth",
                      "cam-cgi-unauth", "cam-cgi-default-creds"}


def _mark_exposure(svc, name, product, kind, version, script_id, crit_output):
    if not svc.name:
        svc.name = name
    if not svc.product:
        svc.product = product
    if version and not svc.version:
        svc.version = version
        svc.cve_skip = False
    if "exposure" not in svc.sources:
        svc.sources.append("exposure")
    if kind == "open":
        svc.confidence = "high"
        svc.extrainfo = "UNAUTHENTICATED access"
        svc.scripts.append({"id": script_id, "output": crit_output})
    else:
        auth_id = script_id.replace("-unauth", "-auth").replace("-anon", "-auth")
        svc.scripts.append({"id": auth_id,
                            "output": f"{product} detected; authentication is "
                                      "enforced (the read-only probe was refused "
                                      "without credentials)."})


async def check_exposure(cfg: ScanConfig, host: str, svc: Service) -> None:
    """Run the read-only unauth check that matches this service, if any."""
    name = (svc.name or "").lower()
    port = svc.port

    if "redis" in name or port in _REDIS_PORTS:
        res = await redis_probe(host, port, cfg.timeout)
        if res:
            _mark_exposure(svc, "redis", "Redis", res[0], res[1], "redis-unauth",
                f"Redis reachable WITHOUT authentication (INFO succeeded). An "
                f"unauthenticated client can read and overwrite every key and, "
                f"on common deployments, gain code execution (CONFIG SET dir + "
                f"module load / cron / webshell write) = full host compromise. "
                f"Set requirepass or ACLs, bind to localhost, firewall {port}.")
        return

    if "memcache" in name or port in _MEMCACHED_PORTS:
        res = await memcached_probe(host, port, cfg.timeout)
        if res:
            _mark_exposure(svc, "memcached", "Memcached", res[0], res[1],
                "memcached-unauth",
                f"memcached reachable WITHOUT authentication (answered version). "
                f"Any client can read and poison cached data, and the UDP/stats "
                f"surface enables large reflection DDoS. Enable SASL, bind to "
                f"localhost, disable UDP, firewall {port}.")
        return

    if "mongo" in name or port in _MONGO_PORTS:
        res = await mongodb_probe(host, port, cfg.timeout)
        if res:
            _mark_exposure(svc, "mongodb", "MongoDB", res[0], res[1],
                "mongodb-unauth",
                f"MongoDB reachable WITHOUT authentication (listDatabases "
                f"succeeded). An unauthenticated client can read and modify every "
                f"database. Enable authorization, bind to localhost, firewall "
                f"{port}.")
        return

    if "rtsp" in name or port in _RTSP_PORTS or port in _RTSPS_PORTS:
        rtsp_tls = (bool(svc.tls) or "rtsps" in name or "ssl" in name
                    or port in _RTSPS_PORTS)
        info = await rtsp_probe(host, port, cfg.timeout, tls=rtsp_tls)
        if info is not None:
            scheme = "rtsps" if rtsp_tls else "rtsp"
            tlsnote = " over TLS (RTSPS)" if rtsp_tls else ""
            if not svc.name:
                svc.name = scheme
            if not svc.product:
                svc.product = info["server"] or scheme.upper()
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            banner = f" ({info['server']})" if info["server"] else ""
            if info["unauth"]:
                svc.confidence = "high"
                svc.extrainfo = f"UNAUTHENTICATED {scheme.upper()} stream"
                svc.scripts.append({"id": "rtsp-unauth", "output":
                    f"RTSP stream accessible WITHOUT authentication{banner}"
                    f"{tlsnote}: an unauthenticated DESCRIBE of "
                    f"{info['unauth_path']} returned SDP. Anyone who can reach "
                    f"{port} can pull the live video/audio feed. Require "
                    f"credentials and restrict {port} to trusted networks."})
            elif info["auth"]:
                realm = f' realm="{info["realm"]}"' if info["realm"] else ""
                svc.scripts.append({"id": "rtsp-auth", "output":
                    f"RTSP detected{banner}{tlsnote}; authentication enforced "
                    f"({info['auth']}{realm}). Unauthenticated DESCRIBE was "
                    f"refused (401)."})
                if getattr(cfg, "cam_creds", True):
                    hit = await rtsp_try_default_creds(host, port, cfg.timeout,
                                                       info, tls=rtsp_tls)
                    if hit:
                        svc.confidence = "high"
                        svc.extrainfo = f"DEFAULT CREDENTIALS ({hit})"
                        svc.scripts.append({"id": "rtsp-default-creds", "output":
                            f"RTSP accepts DEFAULT credentials {hit} "
                            f"({info['auth']} auth): a DESCRIBE of "
                            f"{info['auth_path']} with factory creds returned 200. "
                            f"An attacker can view the feed with well-known "
                            f"credentials. Change the password immediately."})
            else:
                svc.scripts.append({"id": "rtsp-info", "output":
                    f"RTSP server detected{banner}{tlsnote}. Methods: "
                    f"{info['public'] or 'n/a'}. No stream at common paths and no "
                    f"401, so the unauth status is undetermined."})
        return

    # HTTP(S)-based stores. Use TLS when the cert was already grabbed or the
    # port is TLS-only.
    tls = bool(svc.tls) or port in _TLS_EXPOSURE_PORTS

    if "elasticsearch" in name or port in _ES_PORTS:
        res = await elasticsearch_probe(host, port, cfg.timeout, tls)
        if res:
            _mark_exposure(svc, "elasticsearch", "Elasticsearch", res[0], res[1],
                "elasticsearch-unauth",
                f"Elasticsearch reachable WITHOUT authentication (cluster root "
                f"answered). An unauthenticated client can read every index and, "
                f"via _search / _cat, dump all stored documents. Enable the "
                f"security realm (xpack.security), bind to localhost, firewall "
                f"{port}.")
        return

    if "couchdb" in name or port in _COUCHDB_PORTS:
        res = await couchdb_probe(host, port, cfg.timeout, tls)
        if res:
            _mark_exposure(svc, "couchdb", "CouchDB", res[0], res[1],
                "couchdb-unauth",
                f"CouchDB reachable WITHOUT authentication (_all_dbs listed every "
                f"database). An unauthenticated client can read and modify all "
                f"documents; the Admin Party default also allows creating admin "
                f"users. Require admin credentials, bind to localhost, firewall "
                f"{port}.")
        return

    if "docker" in name or port in _DOCKER_PORTS:
        res = await docker_api_probe(host, port, cfg.timeout, tls)
        if res:
            _mark_exposure(svc, "docker", "Docker Engine API", res[0], res[1],
                "docker-api-unauth",
                f"Docker Engine API reachable WITHOUT authentication (/version "
                f"answered). This is equivalent to root on the host: an "
                f"unauthenticated client can run a privileged container that mounts "
                f"the host filesystem. Never expose the TCP socket unauthenticated; "
                f"require TLS client certs (--tlsverify), firewall {port}.")
        return

    if "etcd" in name or port in _ETCD_PORTS:
        res = await etcd_probe(host, port, cfg.timeout, tls)
        if res:
            _mark_exposure(svc, "etcd", "etcd", res[0], res[1],
                "etcd-unauth",
                f"etcd reachable WITHOUT authentication (v2 keyspace readable). "
                f"etcd commonly stores Kubernetes cluster state and Secrets; an "
                f"unauthenticated client can read and overwrite them. Enable client "
                f"cert auth / RBAC, bind to localhost, firewall {port}.")
        return

    if "kubelet" in name or port in _KUBELET_PORTS:
        res = await kubelet_probe(host, port, cfg.timeout, tls)
        if res:
            _mark_exposure(svc, "kubelet", "kubelet", res[0], res[1],
                "kubelet-anon",
                f"kubelet allows ANONYMOUS access (/pods returned the pod list). "
                f"With anonymous auth enabled an attacker can enumerate pods and, "
                f"via /exec and /run, run commands inside containers on this node. "
                f"Set --anonymous-auth=false and --authorization-mode=Webhook, "
                f"firewall {port}.")
        return

    # ONVIF rides HTTP (no dedicated port of its own in most deployments), so it
    # is checked on any web service or a known ONVIF-only port. A single SOAP
    # POST to /onvif/device_service confirms or rules it out.
    if is_web_service(svc) or port in _ONVIF_PORTS:
        otls = is_tls_service(svc)
        info = await onvif_probe(host, port, cfg.timeout, tls=otls)
        if info is not None:
            if not svc.name:
                svc.name = "onvif"
            dev = info.get("device", {})
            label = " ".join(v for v in (dev.get("manufacturer"),
                                         dev.get("model")) if v)
            if label and not svc.product:
                svc.product = label
            if dev.get("firmware") and not svc.version:
                svc.version = _norm_ver(dev["firmware"]) or svc.version
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            if info["unauth"]:
                svc.confidence = "high"
                svc.extrainfo = "UNAUTHENTICATED ONVIF device info"
                svc.scripts.append({"id": "onvif-unauth", "output":
                    f"ONVIF GetDeviceInformation answered WITHOUT authentication "
                    f"({label or 'device'}): make/model/firmware/serial are "
                    f"exposed and the camera's control surface is likely "
                    f"unauthenticated. Require WS-Security on {port}."})
                await _onvif_enum_scripts(svc, host, port, cfg.timeout, otls, None)
            elif info["auth"]:
                svc.scripts.append({"id": "onvif-auth", "output":
                    "ONVIF device detected; GetDeviceInformation requires "
                    "authentication (WS-UsernameToken)."})
                if getattr(cfg, "cam_creds", True):
                    hit = await onvif_try_default_creds(
                        host, port, cfg.timeout, info, tls=otls)
                    if hit:
                        user, pw, dev2 = hit
                        creds = f"{user}:{pw or '<blank>'}"
                        lbl2 = " ".join(v for v in (dev2.get("manufacturer"),
                                                    dev2.get("model")) if v)
                        if lbl2 and (not svc.product or svc.product == "RTSP"):
                            svc.product = lbl2
                        if dev2.get("firmware") and not svc.version:
                            svc.version = _norm_ver(dev2["firmware"]) or svc.version
                        svc.confidence = "high"
                        svc.extrainfo = f"DEFAULT CREDENTIALS ({creds})"
                        svc.scripts.append({"id": "onvif-default-creds", "output":
                            f"ONVIF accepts DEFAULT credentials {creds}: a "
                            f"WS-UsernameToken GetDeviceInformation returned the "
                            f"device info ({lbl2 or 'device'}). An attacker gains "
                            f"the camera's management API (media URIs, users, "
                            f"PTZ). Change the password immediately."})
                        created = info.get("created") or _utcnow_iso()
                        await _onvif_enum_scripts(
                            svc, host, port, cfg.timeout, otls,
                            lambda: _onvif_ws_security(user, pw, created))
            else:
                svc.scripts.append({"id": "onvif-info", "output":
                    "ONVIF device_service detected (GetSystemDateAndTime "
                    "answered); device-info access undetermined."})
        # camera HTTP surface -- ONVIF present, or any camera signal on this web
        # port (catches standalone HTTP cameras with no ONVIF).
        if info is not None or _looks_like_camera(svc):
            snap = await camera_snapshot_probe(host, port, cfg.timeout, otls)
            if snap:
                svc.confidence = "high"
                if "exposure" not in svc.sources:
                    svc.sources.append("exposure")
                if not svc.extrainfo:
                    svc.extrainfo = "UNAUTHENTICATED camera snapshot"
                svc.scripts.append({"id": "camera-snapshot-unauth", "output":
                    f"Live camera snapshot retrievable WITHOUT authentication: "
                    f"GET {snap} returned a JPEG of the current view. Anyone who "
                    f"can reach {port} can watch stills of the feed. Require "
                    f"authentication and restrict {port} to trusted networks."})
            for f in await vendor_cgi_probe(host, port, cfg.timeout, otls,
                                            getattr(cfg, "cam_creds", True)):
                svc.confidence = "high"
                if "exposure" not in svc.sources:
                    svc.sources.append("exposure")
                if f["model"]:
                    cur = (svc.product or "").strip().lower()
                    # upgrade a bare vendor banner / generic placeholder to the
                    # precise "Vendor Model"; don't clobber a real product string
                    if (not cur or cur == f["vendor"].lower()
                            or cur in ("rtsp", "rtsps", "onvif", "ip camera",
                                       "ipcam", "camera")):
                        svc.product = f"{f['vendor']} {f['model']}".strip()
                elif not svc.product:
                    svc.product = f["vendor"]
                if f["fw"] and not svc.version:
                    # camera fw often has a 'V' prefix (V5.5.800); drop the
                    # leading non-digits so _norm_ver can anchor on the number
                    nv = _norm_ver(re.sub(r"^[^\d]*", "", f["fw"]))
                    if nv:
                        svc.version = nv
                        svc.cve_skip = False
                detail = (f"{f['vendor']} {f['model']}".strip()
                          + (f" fw {f['fw']}" if f["fw"] else ""))
                if f["creds"] is None:
                    if not svc.extrainfo:
                        svc.extrainfo = "UNAUTHENTICATED camera CGI"
                    svc.scripts.append({"id": "cam-cgi-unauth", "output":
                        f"{f['vendor']} management CGI {f['path']} returned device "
                        f"info WITHOUT authentication ({detail or 'device'}). The "
                        f"HTTP admin API is reachable unauthenticated; require "
                        f"credentials and restrict {port}."})
                else:
                    svc.extrainfo = f"DEFAULT CREDENTIALS ({f['creds']})"
                    svc.scripts.append({"id": "cam-cgi-default-creds", "output":
                        f"{f['vendor']} management CGI {f['path']} accepts DEFAULT "
                        f"credentials {f['creds']} ({detail or 'device'}): an "
                        f"attacker gains the camera admin API with well-known "
                        f"credentials. Change the password immediately."})
        return


async def run_exposure_checks(cfg: ScanConfig, host: str,
                              services: list[Service]) -> None:
    """Read-only unauth-access checks over EVERY open service, not just the
    under-identified ones: a service nmap named perfectly can still be exposed."""
    open_svcs = [s for s in services if s.state == "open"]
    if not open_svcs:
        return
    sem = asyncio.Semaphore(cfg.concurrency)

    async def one(svc: Service):
        async with sem:
            try:
                await check_exposure(cfg, host, svc)
            except Exception as e:  # noqa: BLE001
                utils.debug(f"exposure :{svc.port} err {e}")

    await asyncio.gather(*(one(s) for s in open_svcs))

    # Host-level ONVIF WS-Discovery (UDP 3702, active unicast Probe). Runs once
    # per host regardless of whether 3702 was port-scanned, so it surfaces
    # cameras/NVRs that a default TCP scan would miss. Read-only; a non-answer
    # just times out. A hit lands on the udp/3702 service (created if absent).
    try:
        wsd = await wsdiscovery_probe(host, 3702, min(cfg.timeout, 3.0))
    except Exception:  # noqa: BLE001
        wsd = None
    if wsd:
        svc = next((s for s in services
                    if s.port == 3702 and s.proto == "udp"), None)
        if svc is None:
            svc = Service(port=3702, proto="udp", state="open", name="ws-discovery")
            services.append(svc)
        if "exposure" not in svc.sources:
            svc.sources.append("exposure")
        bits = [f"Types: {wsd['types']}" if wsd["types"] else "",
                f"Scopes: {wsd['scopes']}" if wsd["scopes"] else "",
                f"XAddrs: {wsd['xaddrs']}" if wsd["xaddrs"] else ""]
        svc.scripts.append({"id": "ws-discovery", "output":
            "ONVIF WS-Discovery answered a unicast Probe (UDP 3702): "
            + "; ".join(b for b in bits if b)
            + ". The device advertises its type/name/location and the "
              "device_service URL without authentication."})

    hits = [s for s in services
            if any(sc.get("id", "") in EXPOSURE_ALERT_IDS for sc in s.scripts)]
    if hits:
        utils.warn(f"UNAUTHENTICATED exposure on "
                   f"{', '.join(str(s.port) for s in hits)} "
                   f"(see scripts.txt / scan.json)")


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


# Version endpoints for apps that are recognizable by name but hide their
# version from the landing page. Data-driven and product-agnostic: add an app
# by adding a (path, one-group regex) row -- the probing mechanism below needs
# no per-app code. Only queried when such an app is identified without a version.
_VERSION_PROBES = {
    "grafana": ("/api/health", re.compile(r'"version"\s*:\s*"([0-9][0-9.]+)"')),
    # WordPress exposes its version through the generator meta on any rendered
    # page (already parsed into aux); readme.html carries no reliable version
    # line and its GPL text ("version 2") invites a wrong match, so no probe.
    "drupal": ("/CHANGELOG.txt", re.compile(r"Drupal\s+([0-9][0-9.]+)", re.I)),
    "joomla": ("/administrator/manifests/files/joomla.xml",
               re.compile(r"<version>\s*([0-9][0-9.]+)", re.I)),
}


async def _probe_app_version(http, host: str, port: int, tls: bool,
                             app: str) -> str:
    """Fetch an app's version endpoint (if one is registered) and extract it."""
    spec = _VERSION_PROBES.get(app.strip().lower())
    if not spec:
        return ""
    path, rx = spec
    scheme = "https" if tls else "http"
    try:
        r = await http.fetch(f"{scheme}://{host}:{port}{path}",
                             method="GET", read_body=True)
    except Exception:  # noqa: BLE001
        return ""
    if not getattr(r, "ok", False) or getattr(r, "status", 0) != 200:
        return ""
    m = rx.search(r.text or "")
    return m.group(1) if m else ""


# Tomcat prints its real version in the default error-page footer
# ("<h3>Apache Tomcat/5.5.26</h3>") and in RELEASE-NOTES.txt ("Apache Tomcat
# Version 5.5.26"). We require major >= 3 so the Coyote protocol version "1.1"
# (or any 1.x/2.x noise) can never be mistaken for a server version.
_TOMCAT_FOOTER_RX = re.compile(r"Apache Tomcat/([0-9][0-9.]+)", re.I)
_TOMCAT_RELNOTES_RX = re.compile(r"Apache Tomcat\s+Version\s+([0-9][0-9.]+)", re.I)


def _valid_tomcat_version(ver: str) -> str:
    """Accept only a plausible Tomcat server version (major >= 3); '' otherwise.
    Rejects the Coyote connector protocol version (1.1) outright."""
    ver = (ver or "").strip().rstrip(".")
    m = re.match(r"(\d+)", ver)
    if not m or int(m.group(1)) < 3:
        return ""
    return ver


async def _probe_tomcat_version(http, host: str, port: int, tls: bool) -> str:
    """Recover the true Apache Tomcat version from the server itself.

    nmap only gives us the Coyote connector protocol version, so we ask Tomcat
    directly: a random path trips the default error page (whose footer carries
    the version), with RELEASE-NOTES.txt as a fallback. Returns '' when the
    version is not disclosed -- the caller then suppresses CVE correlation
    rather than guess.
    """
    import random
    scheme = "https" if tls else "http"
    rand = f"/webrecon-probe-{random.randint(100000, 999999)}"
    attempts = [(rand, _TOMCAT_FOOTER_RX),
                ("/RELEASE-NOTES.txt", _TOMCAT_RELNOTES_RX)]
    for path, rx in attempts:
        try:
            r = await http.fetch(f"{scheme}://{host}:{port}{path}",
                                 method="GET", read_body=True)
        except Exception:  # noqa: BLE001
            continue
        body = getattr(r, "text", "") or ""     # error pages are 404/500 -> no
        if not body:                            # status gate; the body is what
            continue                            # carries the version
        # try the path's own regex, then the generic footer regex as a backstop
        for candidate in (rx, _TOMCAT_FOOTER_RX):
            m = candidate.search(body)
            if m:
                ver = _valid_tomcat_version(m.group(1))
                if ver:
                    return ver
    return ""


# ---------------------------------------------------------------------------
# Discovery path-probes: apps that carry a CPE but ship NO HTTP fingerprint
# signal in wappalyzergo (so the catalog can never find them, rendered or not).
# We hit one known read-only endpoint per app and identify it (+ version where
# the app discloses it). Each label must match a cve._CPE_MAP key so a versioned
# hit CVE-correlates. Product-agnostic: add an app by adding a row.
# ---------------------------------------------------------------------------
# Each row: (label, token, attempts). `label` must match a cve._CPE_MAP key.
# `token` is a distinctive substring of the app: when a probe confirms the app
# but can't read a version, and nmap already put a version on this very service
# under a differently-worded product that carries `token`, we adopt that version
# so the correctly-named aux product still CVE-correlates.
_DISCOVERY_PROBES = [
    # Apache Solr: the admin system endpoint returns JSON with the exact version
    ("Solr", "solr", [
        ("/solr/admin/info/system?wt=json",
         re.compile(r'"(?:solr-spec-version|lucene)"', re.I),
         re.compile(r'"solr-spec-version"\s*:\s*"([0-9][0-9.]+)"')),
    ]),
    # Oracle WebLogic: the admin console login page names the product AND, on
    # 12.x/14.x, prints the exact build unauthenticated in a page footer
    #   <p id="footerVersion">WebLogic Server Version: 12.2.1.3.0</p>
    # (lab-confirmed on vulhub/weblogic:12.2.1.3-2018). Capture it when present;
    # a hardened console that omits the footer leaves the probe presence-only,
    # and the version (when known) is then inherited from nmap via `token`.
    ("Oracle WebLogic Server", "weblogic", [
        ("/console/login/LoginForm.jsp",
         re.compile(r"WebLogic", re.I),
         re.compile(r"WebLogic Server Version:\s*([0-9][0-9.]+)")),
    ]),
    # Appwrite: the health endpoint returns a bare {"version":"x.y.z"} object.
    ("Appwrite", "appwrite", [
        ("/v1/health/version",
         re.compile(r'^\s*\{\s*"version"\s*:\s*"[0-9]'),
         re.compile(r'"version"\s*:\s*"([0-9][0-9.]+)"')),
    ]),
]


async def _discover_app(http, host: str, port: int, tls: bool,
                        label: str, attempts) -> list | None:
    scheme = "https" if tls else "http"
    for path, detect_rx, ver_rx in attempts:
        try:
            r = await http.fetch(f"{scheme}://{host}:{port}{path}",
                                 method="GET", read_body=True)
        except Exception:  # noqa: BLE001
            continue
        if getattr(r, "status", 0) != 200:
            continue
        body = getattr(r, "text", "") or ""
        if not body or not detect_rx.search(body):
            continue
        ver = ""
        if ver_rx is not None:
            m = ver_rx.search(body)
            if m:
                ver = _norm_ver(m.group(1))
        return [label, ver]
    return None


async def run_discovery_probes(cfg: ScanConfig, http, host: str,
                               services: list[Service]) -> None:
    """Read-only discovery path-probes over every open web service (Solr,
    Oracle WebLogic, Appwrite). Runs in the fingerprint phase, before CVE, so a
    versioned hit correlates. One GET per app; a miss is a plain 404."""
    web = [s for s in services if s.state == "open" and is_web_service(s)]
    if not web:
        return
    sem = asyncio.Semaphore(cfg.concurrency)

    async def one(svc: Service):
        tls = is_tls_service(svc)
        for label, token, attempts in _DISCOVERY_PROBES:
            async with sem:
                try:
                    hit = await _discover_app(http, host, svc.port, tls,
                                              label, attempts)
                except Exception as e:  # noqa: BLE001
                    utils.debug(f"discovery :{svc.port} {label}: {e}")
                    continue
            if not hit:
                continue
            name, ver = hit
            same_primary = token in f"{svc.product} {svc.name}".lower()
            # the probe confirmed the app but read no version: adopt nmap's
            # version for this service when its product/name is the same app
            # (so the correctly-named aux product can still CVE-correlate).
            if not ver and svc.version and same_primary:
                ver = _norm_ver(svc.version)
            # conversely, when the probe read a version and this service IS that
            # app, promote it onto svc.version. Otherwise the primary product
            # (e.g. nmap's "Apache Solr" with no version) would CVE-correlate as
            # a wildcard CPE and pull EVERY CVE for the product, including ones
            # that do not apply to this version.
            if ver and not svc.version and same_primary:
                svc.version = ver
                svc.cve_skip = False
            same = next((p for p in svc.aux if p[0].lower() == name.lower()), None)
            if same is None:
                svc.aux.append([name, ver])
            elif ver and not same[1]:
                same[1] = ver
            if "discovery" not in svc.sources:
                svc.sources.append("discovery")
            svc.scripts.append({"id": "discovery-app",
                                "output": f"{name}{(' ' + ver) if ver else ''} "
                                          f"detected via a known endpoint probe"})

    await asyncio.gather(*(one(s) for s in web))


# ---------------------------------------------------------------------------
# Technology fingerprint catalog (generated from projectdiscovery/wappalyzergo,
# MIT; see scripts/build_tech_catalog.py). Gives breadth our hand-written
# _HTTP_BODY_SIGS can't: ~270 CVE-correlatable web apps with header/meta/script/
# html detection patterns and version-capture groups. Loaded once, lazily.
# ---------------------------------------------------------------------------
import json as _json
import os as _os

_CATALOG: dict | None = None
_META_TAG_RX = re.compile(
    r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']', re.I)


def _load_catalog() -> dict:
    global _CATALOG
    if _CATALOG is not None:
        return _CATALOG
    path = _os.path.join(_os.path.dirname(__file__), "data",
                         "tech_fingerprints.json")
    try:
        raw = _json.load(open(path, encoding="utf-8"))
        apps = raw.get("apps", {})
        for entry in apps.values():
            for s in entry.get("sigs", []):
                try:
                    s["_c"] = re.compile(s["re"], re.I)
                except re.error:
                    s["_c"] = None
        _CATALOG = apps
    except Exception as e:  # noqa: BLE001
        utils.debug(f"tech catalog load failed: {type(e).__name__}")
        _CATALOG = {}
    return _CATALOG


def catalog_js_vars() -> list[str]:
    """Every JavaScript global path any catalog app looks for (deduped). A
    renderer evaluates window.<path> for each and passes the results to
    match_catalog as js_globals."""
    seen = set()
    for entry in _load_catalog().values():
        for s in entry.get("sigs", []):
            if s.get("loc") == "js":
                seen.add(s["key"])
    return sorted(seen)


def catalog_dom_specs() -> list[tuple]:
    """Every DOM check any catalog app looks for, as (selector, mode, attr).
    A renderer resolves each selector and passes dom_eval to match_catalog."""
    seen = set()
    for entry in _load_catalog().values():
        for s in entry.get("sigs", []):
            if s.get("loc") == "dom":
                seen.add((s["sel"], s["mode"], s.get("attr")))
    return sorted(seen)


def match_catalog(headers, body: str, js_globals: dict | None = None,
                  dom_eval: dict | None = None) -> list[list[str]]:
    """Return [[app, version], ...] for every catalog app whose signatures match.

    headers/body cover the plain-HTTP signals (header/meta/cookie/script/html).
    js_globals ({var.path: stringified value}) and dom_eval ({selector:
    {"exists":bool, "attrs":{name:val}, "text":str}}) cover the rendered-page
    signals; when they are None (a plain GET) every js/dom sig is simply
    skipped, so a non-rendering caller behaves exactly as before."""
    cat = _load_catalog()
    if not cat:
        return []
    metas = {m.group(1).lower(): m.group(2)
             for m in _META_TAG_RX.finditer(body or "")}
    setcookie = ""
    try:
        setcookie = (headers.get("set-cookie", "") or "").lower()
    except Exception:  # noqa: BLE001
        pass
    out: list[list[str]] = []
    for name, entry in cat.items():
        ver = ""
        hit = False
        for s in entry.get("sigs", []):
            rx = s.get("_c")
            if rx is None:
                continue
            loc = s["loc"]
            if loc == "header":
                target = ""
                try:
                    target = headers.get(s["key"], "") or ""
                except Exception:  # noqa: BLE001
                    target = ""
                if not target:
                    continue
            elif loc == "meta":
                if s["key"] not in metas:
                    continue
                target = metas[s["key"]]
            elif loc == "cookie":
                if s["key"] not in setcookie:
                    continue
                target = setcookie
            elif loc == "js":
                if js_globals is None or s["key"] not in js_globals:
                    continue
                target = str(js_globals.get(s["key"]) or "")
            elif loc == "dom":
                if dom_eval is None:
                    continue
                d = dom_eval.get(s["sel"])
                if not d or not d.get("exists"):
                    continue
                mode = s.get("mode")
                if mode == "exists":
                    target = ""          # presence already confirmed
                elif mode == "attr":
                    val = (d.get("attrs") or {}).get(s.get("attr"))
                    if val is None:
                        continue
                    target = str(val)
                elif mode == "text":
                    target = str(d.get("text") or "")
                else:
                    continue
            else:                               # script / html -> whole body
                target = body or ""
            if loc == "dom" and s.get("mode") == "exists":
                m = True                        # presence sig, no regex needed
            else:
                m = rx.search(target)
                if not m:
                    continue
            hit = True
            if s["v"] and not ver and m is not True:
                try:
                    g = m.group(s["v"])
                    if g:
                        ver = _norm_ver(g)
                except (re.error, IndexError):
                    pass
        if hit:
            out.append([name, ver])
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
    # app-level body/header signatures. A web app (WordPress, Grafana, ...) runs
    # on the same port as the server (often Apache/nginx), so rather than
    # overwrite the server product we add the app as an aux CVE subject -- then
    # BOTH the server and the app are correlated. If the server itself was
    # unidentified, the first app also becomes the primary identity.
    tech = []
    app_aux: list[list[str]] = []
    body = r.text or ""
    for rx, label in _HTTP_BODY_SIGS:
        m = rx.search(body) or rx.search(server + " " + powered)
        if not m:
            continue
        if label is None:  # generator meta -> "Name X.Y.Z"
            gen = m.group(1).strip()
            tech.append(gen)
            gm = re.match(r"([A-Za-z][A-Za-z0-9 ._-]*?)\s*v?([0-9][0-9.]+)?\s*$", gen)
            if gm:
                app_aux.append([gm.group(1).strip(), gm.group(2) or ""])
        else:
            tech.append(label)
            ver = m.group(1) if (m.lastindex and (m.group(1) or "")[:1].isdigit()) else ""
            if label.lower() not in ("atlassian",):   # too broad to CVE-map
                app_aux.append([label, ver])

    # broad catalog detection (generated from wappalyzergo, MIT): adds
    # CVE-mappable web apps with versions well beyond the hand-written sigs.
    for cname, cver in match_catalog(r.headers, body):
        tech.append(cname)
        app_aux.append([cname, cver])

    # register recognized apps as aux products (deduped, preferring a version)
    if app_aux:
        aux = info.get("aux", [])
        for name, ver in app_aux:
            same = next((p for p in aux if p[0].lower() == name.lower()), None)
            if same is None:
                aux.append([name, ver])
            elif ver and not same[1]:
                same[1] = ver
        info["aux"] = aux
        if not product:                      # server unidentified -> app is it
            product, version = aux[0][0], aux[0][1]
            conf = "medium" if version else "low"
    if tech:
        info["tech"] = sorted(set(tech))

    # fill missing versions from an app version endpoint (table-driven)
    if product and not version and _VERSION_PROBES.get(product.lower()):
        pv = await _probe_app_version(http, host, port, tls, product)
        if pv:
            version, conf = pv, "high"
    for pair in info.get("aux", []):
        if not pair[1] and _VERSION_PROBES.get(pair[0].lower()):
            pv = await _probe_app_version(http, host, port, tls, pair[0])
            if pv:
                pair[1] = pv
                if product.lower() == pair[0].lower() and not version:
                    version = pv

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


def is_web_service(svc) -> bool:
    """True if this open port speaks HTTP(S): by nmap/our name, an HTTP
    fingerprint, or a canonical web/TLS port."""
    name = (svc.name or "").lower()
    return ("http" in name or bool(svc.http)
            or svc.port in _HTTP_PORTS or svc.port in _TLS_PORTS)


def is_tls_service(svc) -> bool:
    """True if this web port is TLS-wrapped (https/ssl name, a grabbed cert, or
    a canonical TLS port)."""
    name = (svc.name or "").lower()
    return ("https" in name or "ssl" in name
            or bool(svc.tls) or svc.port in _TLS_PORTS)


def _merge_render_hits(svc: Service, hits: list[list[str]]) -> None:
    """Fold rendered-page catalog hits onto svc.aux (deduped, preferring a
    version). CVE correlation picks up the version-anchored ones; the script
    note makes every detected app visible even when version-less."""
    if not hits:
        return
    labels = []
    for name, ver in hits:
        labels.append(f"{name} {ver}".strip())
        same = next((p for p in svc.aux if p[0].lower() == name.lower()), None)
        if same is None:
            svc.aux.append([name, ver])
        elif ver and not same[1]:
            same[1] = ver
    if "render" not in svc.sources:
        svc.sources.append("render")
    svc.scripts.append({"id": "render-tech",
                        "output": "rendered-page technology (JS globals / DOM): "
                                  + ", ".join(sorted(set(labels)))})


async def run_render_catalog(cfg: ScanConfig, host: str,
                             services: list[Service]) -> None:
    """Render the root of every open web service and merge JS/DOM-only catalog
    apps (Angular, CKEditor, Kubernetes Dashboard, Vtiger, ...) onto svc.aux, so
    a plain `servicescan --render` run surfaces their versions in the port-scan
    summary and CVE-correlates them -- no full webrecon crawl required. Opt-in
    via cfg.render; a no-op when Playwright is unavailable. Runs before CVE
    correlation so the versioned hits flow straight into it."""
    web = [s for s in services if s.state == "open" and is_web_service(s)]
    if not web:
        return
    try:
        from webrecon.render import RootRenderer
    except Exception as e:  # noqa: BLE001
        utils.debug(f"render import failed: {type(e).__name__}")
        return
    js_vars = catalog_js_vars()
    dom_specs = catalog_dom_specs()
    async with RootRenderer(timeout=max(cfg.timeout, 15.0),
                            user_agent="servicescan") as r:
        if not r.available:
            return
        for svc in web:
            scheme = "https" if is_tls_service(svc) else "http"
            url = f"{scheme}://{utils.with_port(host, svc.port)}/"
            info = await r.eval(url, js_vars, dom_specs)
            if not info:
                continue
            hits = match_catalog(info.get("headers") or {}, info.get("html") or "",
                                 js_globals=info.get("js_globals"),
                                 dom_eval=info.get("dom_eval"))
            _merge_render_hits(svc, hits)
    done = [s for s in web if any(sc.get("id") == "render-tech"
                                  for sc in s.scripts)]
    if done:
        utils.info(f"render: catalog tech detected on "
                   f"{', '.join(str(s.port) for s in done)}")


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

    # 1d) distcc compile daemon (silent binary protocol -> no banner). A
    #     read-only behavioural probe on the canonical port / nmap's distcc tag;
    #     it submits no job, so nothing is executed on the target.
    if (not is_http and svc.name != "shell"
            and ("distcc" in name or svc.port == 3632)):
        if await distcc_probe(host, svc.port, cfg.timeout):
            svc.name = "distccd"
            if not svc.product:
                svc.product = "distcc distributed compiler daemon (likely)"
            # heuristic (no protocol handshake / no job submitted) -> medium
            if svc.confidence != "high":
                svc.confidence = "medium"
            if "distcc" not in svc.sources:
                svc.sources.append("distcc")
            svc.scripts.append({
                "id": "distcc-detect",
                "output": "behaviour consistent with a distcc daemon (distccd) "
                          "on the canonical port 3632 (silent on connect; a "
                          "bad-version DIST header is rejected with an immediate "
                          "data-less close). No job was submitted, so this is a "
                          "heuristic, not a protocol confirmation -- verify the "
                          "daemon and version directly. If distccd is confirmed, "
                          "started without an --allow ACL and reachable from an "
                          "untrusted network, any client can execute arbitrary "
                          "commands (CVE-2004-2687, remote command execution; "
                          "Metasploit unix/misc/distcc_exec). Restrict with "
                          "--allow and a firewall; never expose 3632 to "
                          "untrusted networks."})

    # 1c) Tomcat version recovery. nmap frequently pins a service as Tomcat but
    #     without a usable server version -- either it mislabels it as the Coyote
    #     connector and reports the protocol version ("1.1"), or it names "Apache
    #     Tomcat" with no version at all (the Server header is suppressed by
    #     default). Version-less correlation then dumps EVERY Tomcat CVE (seen on
    #     tomcat:9.0.30 -> 254 CVEs). Tomcat discloses its exact version
    #     unauthenticated in the default error-page footer
    #     ("<h3>Apache Tomcat/9.0.30</h3>"), so recover it from the server and
    #     only then correlate. If a hardened server withholds it, keep the
    #     product label but set cve_skip so correlate() does not flood.
    _tomcat_unversioned = ("tomcat" in (svc.product or "").lower()
                           and not _valid_tomcat_version(svc.version or ""))
    if is_coyote_misattrib(svc) or _tomcat_unversioned:
        realver = await _probe_tomcat_version(host=host, port=svc.port,
                                              http=http, tls=is_tls)
        # drop nmap's misleading coyote_* CPE and any protocol "version"
        svc.cpe = [c for c in svc.cpe
                   if not any(p in (c or "").lower()
                              for p in _COYOTE_CPE_PRODUCTS)]
        svc.product = "Apache Tomcat"      # catalog maps this to apache:tomcat
        if "fingerprint" not in svc.sources:
            svc.sources.append("fingerprint")
        if realver:
            svc.version = realver
            svc.cve_skip = False
            svc.confidence = "high"
            svc.scripts.append({"id": "tomcat-version", "output":
                f"Apache Tomcat {realver} recovered from the server's default "
                f"error-page footer (nmap exposed no server version; its banner "
                f"shows only the suppressed header / Coyote connector protocol)."})
        else:
            svc.version = ""
            svc.cve_skip = True            # identified but version undisclosed
            svc.scripts.append({"id": "tomcat-version", "output":
                "Apache Tomcat detected but the server version is not disclosed "
                "(Server header suppressed and the default error page hardened). "
                "CVE correlation suppressed to avoid version-less false "
                "positives; determine the Tomcat version to assess exposure."})

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
    progress = utils.Progress("fingerprint")
    done = 0

    async def one(svc: Service):
        nonlocal done
        async with sem:
            try:
                await fingerprint_service(cfg, http, host, svc)
            except Exception as e:  # noqa: BLE001
                utils.debug(f"fingerprint :{svc.port} err {e}")
            finally:
                done += 1
                progress.update(done, len(targets), f":{svc.port}")

    await asyncio.gather(*(one(s) for s in targets))
    progress.finish()
    improved = sum(1 for s in targets if s.version)
    utils.good(f"fingerprint done ({improved}/{len(targets)} now have a version)")
