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
import os
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


# PostgreSQL (TCP 5432). A protocol-3.0 StartupMessage with no password lets the
# backend declare its authentication method without a credential ever being
# sent: AuthenticationOk (subtype 0) means pg_hba matched `trust`, i.e. ANY
# client that can reach the port gets a session with no password = full unauth
# read/write (an alert); subtypes 3/5/10 (password/md5/SCRAM) mean auth is
# enforced (informational posture). Wire format per the PostgreSQL frontend/
# backend protocol ("Message Formats"): StartupMessage is a length + protocol
# 196608 + NUL-terminated key/value pairs; every backend reply is a type byte +
# Int32 length. On trust we stop at AuthenticationOk and never issue a query.
def _pg_startup(user: str, database: str) -> bytes:
    params = (b"user\x00" + user.encode() + b"\x00"
              + b"database\x00" + database.encode() + b"\x00\x00")
    body = (196608).to_bytes(4, "big") + params
    return (len(body) + 4).to_bytes(4, "big") + body


_PG_AUTH = {0: "trust", 2: "kerberos", 3: "password", 5: "md5", 6: "scm",
            7: "gss", 9: "sspi", 10: "scram"}


async def postgres_probe(host: str, port: int, timeout: float):
    """PostgreSQL unauthenticated StartupMessage. Returns
    {auth, version, sqlstate, detail} or None. No credential is sent; a `trust`
    (AuthenticationOk) result is read and the session is then dropped."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:  # noqa: BLE001
        return None
    info = {}
    try:
        writer.write(_pg_startup("postgres", "postgres"))
        await writer.drain()

        async def read_msg():
            hdr = await reader.readexactly(5)
            n = int.from_bytes(hdr[1:5], "big") - 4
            body = await reader.readexactly(n) if 0 < n <= 65535 else b""
            return hdr[0:1], body

        for _ in range(8):
            try:
                t, body = await asyncio.wait_for(read_msg(), timeout=timeout)
            except Exception:  # noqa: BLE001
                break
            if t == b"R" and len(body) >= 4:
                info["auth"] = _PG_AUTH.get(int.from_bytes(body[0:4], "big"),
                                            "other")
                if info["auth"] != "trust":
                    break                 # auth demanded -> stop, send nothing
            elif t == b"S":               # ParameterStatus (server_version etc.)
                kv = body.split(b"\x00")
                if len(kv) >= 2 and kv[0] == b"server_version":
                    info["version"] = kv[1].decode("latin-1", "replace")
            elif t == b"E":               # ErrorResponse -> auth enforced / refused
                info.setdefault("auth", "enforced")
                for f in body.split(b"\x00"):
                    if f[0:1] == b"C":
                        info["sqlstate"] = f[1:].decode("latin-1", "replace")
                    elif f[0:1] == b"M":
                        info["detail"] = f[1:].decode("latin-1", "replace")
                break
            elif t == b"Z":               # ReadyForQuery -> trust session is up
                break
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass
    return info or None


# MySQL / MariaDB (TCP 3306). The server sends its HandshakeV10 greeting the
# instant the TCP connection opens -- before the client writes anything -- so
# reading it leaks the server version (CVE anchor), the default auth plugin and
# the TLS capability (CLIENT_SSL) without any authentication being attempted.
# Informational only (no credential is ever sent, no login completed). Packet:
# 3-byte little-endian length + 1-byte sequence + payload; payload = protocol
# version (0x0A) + NUL server version + conn-id(4) + auth-data-1(8) + filler(1)
# + cap-lower(2) [+ charset(1) + status(2) + cap-upper(2) + auth-data-len(1) +
# reserved(10) + auth-data-2 + plugin-name]. Layout per the MySQL/MariaDB
# client-server protocol; CLIENT_SSL=0x800, SECURE_CONNECTION=0x8000,
# PLUGIN_AUTH=0x80000.
async def mysql_probe(host: str, port: int, timeout: float):
    """Read the server-initiated MySQL/MariaDB handshake (nothing is sent).
    Returns {version, plugin, tls, err} or None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:  # noqa: BLE001
        return None
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
    except Exception:  # noqa: BLE001
        data = b""
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass
    if len(data) < 5:
        return None
    plen = int.from_bytes(data[0:3], "little")
    payload = data[4:4 + plen] if plen else data[4:]
    if not payload:
        return None
    if payload[0] == 0xFF:                       # ERR packet (policy refusal)
        return {"err": payload[3:].decode("latin-1", "replace").strip("\x00")}
    if payload[0] != 0x0A:
        return None
    end = payload.find(b"\x00", 1)
    if end < 0:
        return None
    version = payload[1:end].decode("latin-1", "replace")
    if not any(ch.isdigit() for ch in version):
        return None
    out = {"version": version, "plugin": "", "tls": None}
    try:
        i = end + 1 + 4 + 8 + 1                   # conn-id, auth-data-1, filler
        cap = int.from_bytes(payload[i:i + 2], "little")
        i += 2
        if len(payload) >= i + 5:
            i += 1 + 2                            # charset, status
            cap |= int.from_bytes(payload[i:i + 2], "little") << 16
            i += 2
            apd_len = payload[i]
            i += 1 + 10                           # auth-data-len, reserved(10)
            if cap & 0x8000:                      # SECURE_CONNECTION
                i += max(13, apd_len - 8)
            if cap & 0x80000:                     # PLUGIN_AUTH
                z = payload.find(b"\x00", i)
                out["plugin"] = payload[i:(z if z >= 0 else len(payload))] \
                    .decode("latin-1", "replace")
        out["tls"] = bool(cap & 0x800)
    except Exception:  # noqa: BLE001
        pass
    return out


# Microsoft SQL Server. Two unauthenticated, read-only identity leaks:
#   * TCP 1433 TDS PRELOGIN (MS-TDS 2.2.6.5): a PRELOGIN request (packet type
#     0x12) is answered (type 0x04) with the server VERSION and its ENCRYPTION
#     posture -- no login is attempted. ENCRYPTION 0x02 (NOT_SUP) means the
#     instance offers no TLS, so login credentials would transit in cleartext.
#   * UDP 1434 SQL Server Browser (MC-SQLR): a single 0x02 datagram is answered
#     with a semicolon-delimited list of every instance's name, version and TCP
#     port -- a classic unauthenticated enumeration leak.
# Both are informational (version anchors CVE correlation; encryption posture is
# a hardening note). ENCRYPTION values 0x00 OFF / 0x01 ON / 0x02 NOT_SUP /
# 0x03 REQ.
_TDS_PRELOGIN = bytes.fromhex("12 01 00 1a 00 00 00 00".replace(" ", "")) + (
    # option table: VERSION[0x00]@11 len6, ENCRYPTION[0x01]@17 len1, 0xFF
    b"\x00" + (11).to_bytes(2, "big") + (6).to_bytes(2, "big")
    + b"\x01" + (17).to_bytes(2, "big") + (1).to_bytes(2, "big")
    + b"\xff"
    + b"\x09\x00\x00\x00\x00\x00"       # VERSION data (client, arbitrary)
    + b"\x00")                          # ENCRYPTION data (ENCRYPT_OFF request)
_TDS_ENC = {0: "off (login-only)", 1: "on", 2: "not supported", 3: "required"}


async def mssql_prelogin_probe(host: str, port: int, timeout: float):
    """TDS PRELOGIN (TCP). Returns {version, encryption} or None. No login."""
    data = await _read_once(host, port, _TDS_PRELOGIN, timeout, nbytes=4096)
    if len(data) < 9 or data[0] != 0x04:       # PRELOGIN response packet type
        return None
    payload = data[8:]
    opts, i = {}, 0
    while i + 5 <= len(payload) and payload[i] != 0xFF:
        tok = payload[i]
        off = int.from_bytes(payload[i + 1:i + 3], "big")
        ln = int.from_bytes(payload[i + 3:i + 5], "big")
        opts[tok] = payload[off:off + ln]
        i += 5
    out = {}
    v = opts.get(0x00, b"")
    if len(v) >= 4:
        out["version"] = f"{v[0]}.{v[1]}.{int.from_bytes(v[2:4], 'big')}"
    enc = opts.get(0x01, b"")
    if enc:
        out["encryption"] = _TDS_ENC.get(enc[0], f"0x{enc[0]:02x}")
    return out or None


async def mssql_browser_probe(host: str, port: int, timeout: float):
    """SQL Server Browser (UDP 1434). Returns a list of instance dicts or None."""
    data = await _udp_query(host, port, b"\x02", timeout)
    if len(data) < 3 or data[0] != 0x05:
        return None
    text = data[3:].decode("latin-1", "replace")
    toks = text.split(";")
    instances, cur = [], {}
    i = 0
    while i + 1 < len(toks):
        key, val = toks[i], toks[i + 1]
        i += 2
        if key == "ServerName" and cur:
            instances.append(cur)
            cur = {}
        if key:
            cur[key] = val
    if cur:
        instances.append(cur)
    return instances or None


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


# --- More HTTP(S) control-plane / ops services. Same read-only GET contract as
# the stores above: confirm the product from a specific marker, then report
# whether its data/admin surface answers without credentials. Each returns
# ("open", version) / ("auth", "") / None, except Vault (by-design-public probe)
# which returns its own dict and is framed as a hardening note, not an alert.
async def prometheus_probe(host: str, port: int, timeout: float, tls: bool):
    """Prometheus (no auth by design -> network-reachable = exposure)."""
    r = await _http_get_once(host, port, "/-/healthy", timeout, tls)
    if not r:
        return None
    status, _, body = r
    if status in (401, 403):
        return ("auth", "")
    if status != 200 or b"Prometheus" not in body:
        return None
    ver = ""
    r2 = await _http_get_once(host, port, "/api/v1/status/buildinfo", timeout, tls)
    if r2 and r2[0] == 200:
        ver = _json_ver(r2[2], "version")
    return ("open", ver)


async def consul_probe(host: str, port: int, timeout: float, tls: bool):
    """Consul agent self-config (readable only when ACLs are disabled/open)."""
    r = await _http_get_once(host, port, "/v1/agent/self", timeout, tls)
    if not r:
        return None
    status, _, body = r
    if status == 200 and b'"Config"' in body and b'"Member"' in body:
        return ("open", _json_ver(body, "Version"))
    if status in (401, 403):
        return ("auth", "")
    return None


async def vault_probe(host: str, port: int, timeout: float, tls: bool):
    """HashiCorp Vault seal-status (public by design). {sealed, version}/None."""
    r = await _http_get_once(host, port, "/v1/sys/seal-status", timeout, tls)
    if not r:
        return None
    status, _, body = r
    if status != 200 or b'"sealed"' not in body or b'"version"' not in body:
        return None
    return {"sealed": b'"sealed":true' in body.replace(b" ", b""),
            "version": _json_ver(body, "version")}


async def rabbitmq_probe(host: str, port: int, timeout: float, tls: bool):
    """RabbitMQ management API /api/overview. ('open', v) when it answers without
    credentials, ('auth', '') when the plugin is present but demands them."""
    r = await _http_get_once(host, port, "/api/overview", timeout, tls)
    if not r:
        return None
    status, headers, body = r
    if status == 200 and (b'"rabbitmq_version"' in body
                          or b'"management_version"' in body):
        return ("open", _json_ver(body, "rabbitmq_version"))
    if status == 401 and "rabbitmq" in headers.get("www-authenticate", "").lower():
        return ("auth", "")
    return None


async def minio_probe(host: str, port: int, timeout: float, tls: bool):
    """MinIO S3 endpoint. ('open','') when anonymous ListBuckets succeeds,
    ('auth','') when MinIO is present but anonymous listing is denied."""
    def _is_minio(hdrs):
        return "minio" in hdrs.get("server", "").lower()

    r = await _http_get_once(host, port, "/minio/health/live", timeout, tls)
    present = bool(r and _is_minio(r[1]))
    r2 = await _http_get_once(host, port, "/", timeout, tls)
    if not present and not (r2 and _is_minio(r2[1])):
        return None
    if r2 and r2[0] == 200 and b"ListAllMyBucketsResult" in r2[2]:
        return ("open", "")
    return ("auth", "")


async def portainer_probe(host: str, port: int, timeout: float, tls: bool):
    """Portainer. ('open', v) when no admin is set yet (anyone can claim it via
    /api/users/admin/init), ('auth', v) when already initialised/protected."""
    r = await _http_get_once(host, port, "/api/system/status", timeout, tls)
    if not (r and r[0] == 200 and b'"Version"' in r[2]):
        r = await _http_get_once(host, port, "/api/status", timeout, tls)
    if not (r and r[0] == 200 and b'"Version"' in r[2]):
        return None                     # not Portainer (no public status endpoint)
    ver = _json_ver(r[2], "Version")
    chk = await _http_get_once(host, port, "/api/users/admin/check", timeout, tls)
    if chk and chk[0] == 404:
        return ("open", ver)            # no admin account exists yet -> claimable
    return ("auth", ver)


async def zookeeper_probe(host: str, port: int, timeout: float):
    """ZooKeeper four-letter-word 'stat' over TCP. ('open', v) when 4lw answers
    with data, ('auth','') when ZK is present but 4lw is whitelist-restricted."""
    data = await _read_once(host, port, b"stat\n", timeout)
    if not data:
        return None
    if b"Zookeeper version:" in data:
        m = re.search(rb"Zookeeper version:\s*([0-9][0-9.]+)", data)
        return ("open", m.group(1).decode() if m else "")
    low = data.lower()
    if b"not in the whitelist" in low or b"is not executed" in low:
        return ("auth", "")
    return None


# ---------------------------------------------------------------------------
# MQTT (TCP 1883, 8883 over TLS). Dependency-free, read-only: we hand-roll an
# MQTT 3.1.1 anonymous CONNECT and read the CONNACK. A broker that answers
# CONNACK 0x00 with no username/password accepts anonymous clients -- an
# unauthenticated peer can then subscribe to '#' and read all telemetry and
# publish commands (critical on IoT/OT). 0x04/0x05 mean auth is enforced. On an
# anonymous accept we additionally SUBSCRIBE to the single broker-version
# metadata topic ($SYS/broker/version) to recover a version for CVE matching --
# never an application topic, and we publish nothing. Wire format verified
# against OASIS MQTT 3.1.1 (CONNECT 0x10 / CONNACK 0x20 0x02 / return codes).
# ---------------------------------------------------------------------------
def _mqtt_rem_len(n: int) -> bytes:
    """Encode an MQTT Remaining Length (variable byte integer)."""
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _mqtt_decode_rem_len(data: bytes, i: int):
    """Decode a Remaining Length at i -> (value, next_index) or (None, i)."""
    mult, val = 1, 0
    for _ in range(4):
        if i >= len(data):
            return None, i
        b = data[i]
        i += 1
        val += (b & 0x7f) * mult
        if not (b & 0x80):
            return val, i
        mult <<= 7
    return None, i


def _mqtt_connect(client_id: bytes = b"servicescan") -> bytes:
    """MQTT 3.1.1 anonymous CONNECT (clean session, no username/password)."""
    # "MQTT" name, protocol level 4, connect flags 0x02 (clean session only),
    # keep-alive 60s.
    var = b"\x00\x04MQTT\x04\x02\x00\x3c"
    payload = len(client_id).to_bytes(2, "big") + client_id
    body = var + payload
    return b"\x10" + _mqtt_rem_len(len(body)) + body


def _mqtt_subscribe(topic: bytes, pid: int = 1) -> bytes:
    """MQTT SUBSCRIBE for one topic filter at QoS 0."""
    body = pid.to_bytes(2, "big") + len(topic).to_bytes(2, "big") + topic + b"\x00"
    return b"\x82" + _mqtt_rem_len(len(body)) + body


def _mqtt_find_publish(buf: bytes, want_topic: bytes):
    """Scan a buffer of MQTT packets for a PUBLISH on want_topic; return its
    payload bytes or None. Handles any QoS (skips the packet id when QoS > 0)."""
    i = 0
    while i < len(buf):
        first = buf[i]
        rl, j = _mqtt_decode_rem_len(buf, i + 1)
        if rl is None or j + rl > len(buf):
            break
        pkt = buf[j:j + rl]
        if (first & 0xf0) == 0x30 and len(pkt) >= 2:   # PUBLISH
            tlen = int.from_bytes(pkt[0:2], "big")
            topic = pkt[2:2 + tlen]
            qos = (first >> 1) & 0x3
            off = 2 + tlen + (2 if qos else 0)
            if topic == want_topic:
                return pkt[off:]
        i = j + rl
    return None


async def mqtt_probe(host: str, port: int, timeout: float, tls: bool):
    """Anonymous MQTT 3.1.1 CONNECT. ('open', version_banner) when the broker
    accepts an anonymous connection (CONNACK 0x00; banner read read-only from
    $SYS/broker/version, '' if the broker does not publish it), ('auth', '')
    when refused for credentials (0x04/0x05), ('detected', '') when refused for
    another reason (0x01/0x02/0x03), or None when the peer is not MQTT."""
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
    try:
        writer.write(_mqtt_connect())
        await writer.drain()
        connack = await asyncio.wait_for(reader.read(8), timeout=timeout)
        if len(connack) < 4 or connack[0] != 0x20 or connack[1] != 0x02:
            return None                                # not an MQTT broker
        rc = connack[3]
        if rc in (0x04, 0x05):
            return ("auth", "")
        if rc != 0x00:
            return ("detected", "")
        # Anonymous connection accepted -- recover the broker version read-only.
        banner = ""
        sub_to = min(timeout, 3.0)
        try:
            writer.write(_mqtt_subscribe(b"$SYS/broker/version"))
            await writer.drain()
            buf = b""
            while len(buf) < 4096:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=sub_to)
                if not chunk:
                    break
                buf += chunk
                pub = _mqtt_find_publish(buf, b"$SYS/broker/version")
                if pub is not None:
                    banner = pub.decode("latin-1", "replace").strip()
                    break
        except Exception:  # noqa: BLE001
            pass
        return ("open", banner)
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# UDP exposure probes (SNMP, IPMI). Both are single-packet, read-only requests
# over UDP. A shared datagram helper sends one payload and waits for one reply;
# a closed port (ICMP unreachable) resolves fast rather than blocking the whole
# timeout, and nothing is ever written/SET on the target.
# ---------------------------------------------------------------------------
async def _udp_query(host: str, port: int, payload: bytes,
                     timeout: float) -> bytes:
    """Send one UDP datagram, return the first reply (b'' on timeout/error)."""
    loop = asyncio.get_event_loop()
    got = loop.create_future()

    class _P(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):  # noqa: ARG002
            if not got.done():
                got.set_result(data)

        def error_received(self, exc):  # noqa: ARG002
            if not got.done():
                got.set_result(b"")    # ICMP port-unreachable -> give up fast

    try:
        transport, _ = await asyncio.wait_for(
            loop.create_datagram_endpoint(_P, remote_addr=(host, port)),
            timeout=timeout)
    except Exception:  # noqa: BLE001
        return b""
    try:
        transport.sendto(payload)
        try:
            return await asyncio.wait_for(got, timeout=timeout)
        except asyncio.TimeoutError:
            return b""
    finally:
        transport.close()


# --- SNMP (UDP 161). A GetRequest for sysDescr.0 answered with the community we
# sent means the agent is readable with a well-known community string -- a full
# read of the device's configuration surface. We hand-build the ASN.1/BER packet
# (no pysnmp dependency) and try v2c then v1 for "public"/"private" at once.
def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _ber_int(n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    else:
        body = n.to_bytes((n.bit_length() // 8) + 1, "big")
        while len(body) > 1 and body[0] == 0 and not (body[1] & 0x80):
            body = body[1:]
    return _ber_tlv(0x02, body)


def _ber_oid(parts: tuple) -> bytes:
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            body += bytes([p])
        else:
            chunks = []
            while p:
                chunks.insert(0, p & 0x7F)
                p >>= 7
            for i in range(len(chunks) - 1):
                chunks[i] |= 0x80
            body += bytes(chunks)
    return _ber_tlv(0x06, body)


def _ber_split(value: bytes) -> list:
    """Split one constructed BER value into its [(tag, content), ...] children."""
    out, i = [], 0
    while i + 1 < len(value):
        tag = value[i]
        l = value[i + 1]
        i += 2
        if l & 0x80:
            nb = l & 0x7F
            l = int.from_bytes(value[i:i + nb], "big")
            i += nb
        out.append((tag, value[i:i + l]))
        i += l
    return out


_SYSDESCR_OID = (1, 3, 6, 1, 2, 1, 1, 1, 0)
_SNMP_COMMUNITIES = ("public", "private")


def _snmp_get(community: str, oid: tuple, version: int, reqid: int) -> bytes:
    """Build an SNMP GetRequest (version 1 == v2c, 0 == v1)."""
    varbind = _ber_tlv(0x30, _ber_oid(oid) + b"\x05\x00")       # OID + NULL value
    pdu = _ber_tlv(0xA0,                                        # 0xA0 GetRequest
                   _ber_int(reqid) + _ber_int(0) + _ber_int(0)  # id, errstat, erridx
                   + _ber_tlv(0x30, varbind))                   # varbind list
    msg = _ber_int(version) + _ber_tlv(0x04, community.encode()) + pdu
    return _ber_tlv(0x30, msg)


def _snmp_sysdescr(data: bytes) -> str | None:
    """Pull sysDescr out of a GetResponse (error-status 0). None if not one."""
    try:
        top = _ber_split(data)
        if not top or top[0][0] != 0x30:
            return None
        msg = _ber_split(top[0][1])                 # [version, community, pdu]
        pdu = next((c for (t, c) in msg if t == 0xA2), None)   # 0xA2 GetResponse
        if pdu is None:
            return None
        parts = _ber_split(pdu)                     # id, errstat, erridx, vbl
        if len(parts) < 4:
            return None
        if parts[1][1] and int.from_bytes(parts[1][1], "big") != 0:
            return None                             # error-status != 0
        vbs = _ber_split(parts[3][1])
        if not vbs:
            return None
        vb = _ber_split(vbs[0][1])                  # [oid, value]
        if len(vb) < 2:
            return None
        return vb[1][1].decode("latin-1", "replace").strip()
    except Exception:  # noqa: BLE001
        return None


async def snmp_probe(host: str, port: int, timeout: float,
                     communities=_SNMP_COMMUNITIES):
    """SNMP sysDescr.0 read. Returns {community, sysdescr, version} on a reply
    with a well-known community, else None. All attempts race in parallel so the
    whole probe is bounded by a single (short) timeout."""
    t = min(timeout, 3.0)
    attempts = [(c, v) for c in communities for v in (1, 0)]   # v2c then v1

    async def one(comm: str, ver: int):
        data = await _udp_query(host, port,
                                _snmp_get(comm, _SYSDESCR_OID, ver, 0x01020304), t)
        if not data:
            return None
        sd = _snmp_sysdescr(data)
        if sd is not None:
            return {"community": comm, "sysdescr": sd,
                    "version": "2c" if ver == 1 else "1"}
        return None

    for r in await asyncio.gather(*(one(c, v) for c, v in attempts)):
        if r:
            return r
    return None


# --- IPMI cipher-zero (UDP 623). IPMI v2.0 "cipher suite 0" disables all
# authentication, integrity and confidentiality: a BMC that accepts an RMCP+
# Open Session Request with every algorithm set to 0 lets anyone open an
# administrative session with no password. We send that request and read the
# Open Session Response status code. Read-only -- we never complete RAKP or
# issue any command, so no session is actually established.
_IPMI_CONSOLE_SESSION_ID = b"\xa4\xa3\xa2\xa0"
_IPMI_OPEN_SESSION_REQ = (
    b"\x06\x00\xff\x07"          # RMCP: version 6, reserved, seq 0xff, class IPMI
    b"\x06"                      # auth type = RMCP+ (format 6)
    b"\x10"                      # payload type = Open Session Request (0x10)
    b"\x00\x00\x00\x00"          # session id   = 0
    b"\x00\x00\x00\x00"          # session seq  = 0
    b"\x20\x00"                  # payload length = 32 (little-endian)
    b"\x00"                      # message tag
    b"\x00"                      # requested max privilege (0 = pick highest)
    b"\x00\x00"                  # reserved
    + _IPMI_CONSOLE_SESSION_ID + # remote console session id
    b"\x00\x00\x00\x08\x00\x00\x00\x00"   # auth payload:  algorithm 0 (none)
    b"\x01\x00\x00\x08\x00\x00\x00\x00"   # integrity payload: algorithm 0 (none)
    b"\x02\x00\x00\x08\x00\x00\x00\x00"   # confidentiality payload: algorithm 0
)


def _ipmi_parse_open_session(data: bytes):
    """Read an RMCP+ Open Session Response. ('open', managed-session-id-hex)
    when cipher-zero is accepted (status 0), ('auth', '') when a BMC answers but
    refuses it (non-zero status), or None when it is not an IPMI response."""
    if len(data) < 18 or data[:4] != b"\x06\x00\xff\x07":
        return None
    if data[5] != 0x11:                 # payload type: Open Session Response
        return None
    status = data[17]                   # RMCP+ status code (0 == no errors)
    if status != 0x00:
        return ("auth", "")
    msid = data[24:28] if len(data) >= 28 else b""
    return ("open", msid[::-1].hex())   # managed system session id (LE on wire)


async def ipmi_cipher_zero_probe(host: str, port: int, timeout: float):
    """Probe a BMC for IPMI 2.0 cipher-suite-0 auth bypass. Returns
    ('open', msid) / ('auth', '') / None (see _ipmi_parse_open_session)."""
    data = await _udp_query(host, port, _IPMI_OPEN_SESSION_REQ, min(timeout, 3.0))
    if not data:
        return None
    return _ipmi_parse_open_session(data)


_REDIS_PORTS = {6379, 6380}
_MEMCACHED_PORTS = {11211}
_MONGO_PORTS = {27017, 27018, 27019}
_POSTGRES_PORTS = {5432, 5433}
_MYSQL_PORTS = {3306}
_MSSQL_PORTS = {1433, 1434}
_ES_PORTS = {9200, 9201}
_COUCHDB_PORTS = {5984, 6984}
_DOCKER_PORTS = {2375, 2376}
_ETCD_PORTS = {2379, 4001}
_KUBELET_PORTS = {10250, 10255}
_PROMETHEUS_PORTS = {9090}
_CONSUL_PORTS = {8500}
_VAULT_PORTS = {8200}
_RABBITMQ_PORTS = {15672}
_MINIO_PORTS = {9000, 9001}
_PORTAINER_PORTS = {9000, 9443}
_ZOOKEEPER_PORTS = {2181}
_MQTT_PORTS = {1883}                              # MQTT over plain TCP
_MQTTS_PORTS = {8883}                             # MQTT over TLS (MQTTS)
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
_ONVIF_PTZ_NS = "http://www.onvif.org/ver20/ptz/wsdl"
_ONVIF_EVENT_NS = "http://www.onvif.org/ver10/events/wsdl"
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


async def _onvif_service_endpoint(host: str, port: int, timeout: float,
                                  tls: bool, mksec, marker: str):
    """Find one ONVIF sub-service endpoint by its wsdl namespace marker (e.g.
    'ver10/media/wsdl', 'ver20/ptz/wsdl', 'ver10/events/wsdl') via GetServices.
    Returns (path, port, tls) only when the device advertises that service, else
    None -- so a fixed (non-PTZ) camera never produces a false PTZ/events claim."""
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
            if marker in blk:
                xa = re.search(r"<(?:\w+:)?XAddr>([^<]+)<", blk, re.I)
                if xa:
                    return _parse_xaddr(xa.group(1).strip(), port, tls)
    return None


async def _onvif_media_endpoint(host: str, port: int, timeout: float,
                                tls: bool, mksec=None):
    """Media endpoint via GetServices; fall back to device_service when absent."""
    ep = await _onvif_service_endpoint(host, port, timeout, tls, mksec,
                                       "ver10/media/wsdl")
    return ep or (_ONVIF_PATH, port, tls)


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


def _parse_onvif_ptz(body: bytes) -> list[dict]:
    """PTZ configurations/nodes -> [{token, name}]. Accepts either the
    GetConfigurations (PTZConfiguration) or GetNodes (PTZNode) shape."""
    text = body.decode("latin-1", "replace")
    out = []
    for tag in ("PTZConfiguration", "PTZNode"):
        for m in re.finditer(
                rf"<(?:\w+:)?{tag}\b([^>]*)>(.*?)</(?:\w+:)?{tag}>",
                text, re.I | re.S):
            attrs, blk = m.group(1), m.group(2)
            tok = re.search(r'token\s*=\s*"([^"]+)"', attrs, re.I)
            name = re.search(r"<(?:\w+:)?Name>([^<]+)<", blk, re.I)
            out.append({"token": tok.group(1).strip() if tok else "",
                        "name": name.group(1).strip() if name else ""})
        if out:
            break
    return out


def _parse_onvif_event_topics(body: bytes) -> list[str]:
    """Topic leaves out of a GetEventProperties TopicSet. ONVIF marks topic
    elements with wstop:topic="true"; we collect their local names."""
    text = body.decode("latin-1", "replace")
    if "TopicSet" not in text:
        return []
    topics = []
    for m in re.finditer(r"<(?:\w+:)?(\w+)\b[^>]*\btopic\s*=\s*\"true\"",
                         text, re.I):
        t = m.group(1)
        if t not in topics:
            topics.append(t)
    return topics or ["(topic set available)"]


async def onvif_get_ptz(host: str, port: int, timeout: float,
                        tls: bool = False, mksec=None) -> list[dict]:
    """PTZ GetConfigurations on the advertised PTZ endpoint (read-only). Empty
    unless the device lists a PTZ service and returns at least one config."""
    ep = await _onvif_service_endpoint(host, port, timeout, tls, mksec,
                                       "ver20/ptz/wsdl")
    if ep is None:
        return []
    sec = mksec() if mksec else ""
    r = await _http_post_once(host, ep[1], ep[0],
        _onvif_envelope(f'<GetConfigurations xmlns="{_ONVIF_PTZ_NS}"/>', sec),
        timeout, ep[2])
    if not (r and r[0] == 200):
        return []
    return _parse_onvif_ptz(r[2])


async def onvif_get_events(host: str, port: int, timeout: float,
                           tls: bool = False, mksec=None) -> list[str]:
    """Events GetEventProperties on the advertised events endpoint (read-only).
    Returns the topic leaves, or empty when the device lists no events service."""
    ep = await _onvif_service_endpoint(host, port, timeout, tls, mksec,
                                       "ver10/events/wsdl")
    if ep is None:
        return []
    sec = mksec() if mksec else ""
    r = await _http_post_once(host, ep[1], ep[0],
        _onvif_envelope(f'<GetEventProperties xmlns="{_ONVIF_EVENT_NS}"/>', sec),
        timeout, ep[2])
    if not (r and r[0] == 200):
        return []
    return _parse_onvif_event_topics(r[2])


async def _onvif_enum_scripts(svc, host: str, port: int, timeout: float,
                              tls: bool, mksec) -> None:
    """Append onvif-users / onvif-media-profiles / onvif-ptz / onvif-events info
    scripts when the read-only Get* calls return data (best effort; silent on
    failure)."""
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
    ptz = await onvif_get_ptz(host, port, timeout, tls, mksec)
    if ptz:
        names = ", ".join((p["name"] or p["token"] or "?") for p in ptz)
        svc.scripts.append({"id": "onvif-ptz", "output":
            f"ONVIF PTZ control available (GetConfigurations returned "
            f"{len(ptz)} configuration(s): {names}). With this access an attacker "
            f"can aim the camera -- ContinuousMove / AbsoluteMove / GotoPreset -- "
            f"to point it away from an area or track a target. (Read-only: no move "
            f"was issued.)"})
    topics = await onvif_get_events(host, port, timeout, tls, mksec)
    if topics:
        svc.scripts.append({"id": "onvif-events", "output":
            "ONVIF event service exposed (GetEventProperties): topics include "
            + ", ".join(topics[:12])
            + ". The event/notification surface reveals motion, tamper, analytics "
              "and digital-I/O state and lets a client subscribe to the camera's "
              "real-time events."})


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
# Vendor private binary protocols (device management channels, read-only detect).
#   Dahua DVRIP/DHIP (TCP 37777): the NetSDK control channel. We send the pre-auth
#     realm request (NO credentials, no login completed -- the first step that
#     asks the device for its login challenge) and confirm a DVRIP/DHIP response;
#     the realm string frequently carries the device serial.
#   Hikvision SDK (TCP 8000): the HCNetSDK control channel. The device greets on
#     connect with a fixed 16-byte handshake, so we send NOTHING and just read it
#     (the nmap "Hikvision IPCam control port" NULL-probe signature).
# Both ports are auth-gated for actual control, so a hit is an informational
# device identification (and a CVE anchor), not an unauth-access alert.
# ---------------------------------------------------------------------------
_DAHUA_DVRIP_PORTS = {37777}
_HIK_SDK_PORTS = {8000}
# DVRIP realm request: type a0 01 00 00, 20 zero bytes, trailer 05 02 01 01 ..a1aa
_DVRIP_REALM_REQ = (b"\xa0\x01\x00\x00" + b"\x00" * 20
                    + b"\x05\x02\x01\x01\x00\x00\xa1\xaa")
_DVRIP_REALM_RX = re.compile(rb"Realm:([^\r\n]*)")
_DVRIP_RANDOM_RX = re.compile(rb"Random:([^\r\n]*)")


def _parse_dvrip(data: bytes):
    """Confirm a Dahua DVRIP/DHIP response and pull the realm (often the device
    serial/name). Returns {realm, random} or None. Recv headers begin 0xb0
    (binary) or 0xf6 (JSON); older firmware answers the realm request in text."""
    if len(data) < 4:
        return None
    rm = _DVRIP_REALM_RX.search(data)
    rnd = _DVRIP_RANDOM_RX.search(data)
    if not (data[0] in (0xB0, 0xF6) or rm or b"Dahua" in data):
        return None
    return {"realm": rm.group(1).decode("latin-1", "replace").strip() if rm else "",
            "random": rnd.group(1).decode("latin-1", "replace").strip() if rnd else ""}


async def dahua_dvrip_probe(host: str, port: int, timeout: float):
    """Pre-auth DVRIP realm request (no credentials). {realm, random}/None."""
    data = await _read_once(host, port, _DVRIP_REALM_REQ, min(timeout, 3.0))
    return _parse_dvrip(data) if data else None


def _hik_sdk_handshake(data: bytes) -> bool:
    """Hikvision SDK control-port greeting: 16 bytes
    00 00 00 10  00 00 00 XX  00 00 00 XX  00 00 00 00  (XX = 0x1e or 0x0d seen
    in the wild; we accept any equal XX pair for forward tolerance)."""
    return (len(data) >= 16 and data[:4] == b"\x00\x00\x00\x10"
            and data[4:7] == b"\x00\x00\x00" and data[8:11] == b"\x00\x00\x00"
            and data[7] == data[11] and data[12:16] == b"\x00\x00\x00\x00")


async def hikvision_sdk_probe(host: str, port: int, timeout: float) -> bool:
    """Connect and read the greeting (send nothing). True on the SDK handshake."""
    data = await _read_once(host, port, b"", min(timeout, 3.0))
    return _hik_sdk_handshake(data)


# ---------------------------------------------------------------------------
# Camera WebSocket video preview (Hikvision ws 7681 / wss 7682, and other camera
# ports). The plugin-free web live-view ships H.264/proprietary video over a
# WebSocket; by design the connection is session/token authenticated, so the
# finding we care about is a device that streams WITHOUT credentials. We do a
# standard RFC6455 upgrade with NO auth and then only READ what the device
# volunteers: if it pushes binary (video) frames unauthenticated, that is an
# anonymous live feed (critical). We never send a PLAY/start command or any
# exploit -- strictly connect + read, like an RTSP DESCRIBE or a snapshot GET.
# ---------------------------------------------------------------------------
_WS_CAM_PORTS = {7681, 7682}
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_accept(key_b64: str) -> str:
    import base64
    import hashlib
    return base64.b64encode(
        hashlib.sha1((key_b64 + _WS_GUID).encode()).digest()).decode()


def _ws_decode_frames(buf: bytes) -> list:
    """Decode server->client WebSocket frames from `buf` -> [(opcode, payload)].
    Server frames are unmasked per RFC6455; a mask is handled defensively. A
    partial trailing frame is ignored."""
    out, i, n = [], 0, len(buf)
    while i + 2 <= n:
        b1 = buf[i + 1]
        opcode = buf[i] & 0x0F
        masked = b1 & 0x80
        ln = b1 & 0x7F
        j = i + 2
        if ln == 126:
            if j + 2 > n:
                break
            ln = int.from_bytes(buf[j:j + 2], "big")
            j += 2
        elif ln == 127:
            if j + 8 > n:
                break
            ln = int.from_bytes(buf[j:j + 8], "big")
            j += 8
        mask = b""
        if masked:
            if j + 4 > n:
                break
            mask = buf[j:j + 4]
            j += 4
        if j + ln > n:
            break
        payload = buf[j:j + ln]
        if masked and mask:
            payload = bytes(c ^ mask[k % 4] for k, c in enumerate(payload))
        out.append((opcode, payload))
        i = j + ln
    return out


async def ws_stream_probe(host: str, port: int, timeout: float, tls: bool,
                          path: str = "/"):
    """Unauthenticated RFC6455 upgrade, then read what the device volunteers.
    Returns a dict:
      {status, upgraded, accept_ok, auth, binary, video_bytes, text}
    or None when the port does not speak WebSocket (no 101/upgrade)."""
    import base64
    import os
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
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
               f"Origin: http://{host}:{port}\r\nUser-Agent: servicescan\r\n\r\n")
        writer.write(req.encode())
        await writer.drain()
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 8192:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            raw += chunk
        if not raw.startswith(b"HTTP/"):
            return None
        head, _, rest = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        try:
            status = int(lines[0].split(b" ")[1])
        except (IndexError, ValueError):
            return None
        hdrs = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(b":")
            if k:
                hdrs[k.strip().lower().decode("latin-1", "replace")] = \
                    v.strip().decode("latin-1", "replace")
        if status in (401, 403):
            return {"status": status, "upgraded": False, "auth": True,
                    "accept_ok": False, "binary": False, "video_bytes": 0,
                    "text": ""}
        if status != 101 or "websocket" not in hdrs.get("upgrade", "").lower():
            return None
        accept_ok = hdrs.get("sec-websocket-accept", "") == _ws_accept(key)
        buf = rest
        try:
            for _ in range(4):
                chunk = await asyncio.wait_for(reader.read(16384),
                                               min(timeout, 2.0))
                if not chunk:
                    break
                buf += chunk
                if any(op == 0x2 and pl for op, pl in _ws_decode_frames(buf)):
                    break
        except asyncio.TimeoutError:
            pass
        frames = _ws_decode_frames(buf)
        video = sum(len(pl) for op, pl in frames if op == 0x2)
        text = next((pl[:120].decode("latin-1", "replace")
                     for op, pl in frames if op == 0x1), "")
        return {"status": 101, "upgraded": True, "auth": False,
                "accept_ok": accept_ok, "binary": video > 0,
                "video_bytes": video, "text": text}
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass


# ttyd (a web-based terminal) also defaults to 7681 -- it serves an HTML page
# over HTTP and a shell WebSocket at /ws. An exposed ttyd without authentication
# is a browser shell = remote code execution, so it is far more severe than a
# camera feed and must be told apart from the camera WebSocket on the same port.
# Detection is strictly read-only: GET / (and, as a backstop, GET /token). We
# NEVER open the /ws shell socket or send the init that spawns the PTY -- the
# auth state of the HTTP layer is enough (ttyd gates with HTTP Basic via -c).
async def ttyd_probe(host: str, port: int, timeout: float, tls: bool):
    """Detect an exposed ttyd web terminal. {'auth': bool} or None. auth=True
    when the HTTP layer demands credentials (401/403), False when it is open.

    ttyd runs on libwebsockets and routes auth before any path, so with -c set
    every path (including /) returns 401 with WWW-Authenticate: Basic
    realm="ttyd" -- that realm is a strong signature for the auth-enforced case.
    An open instance serves its terminal HTML (contains "ttyd"; we send no
    Accept-Encoding so it is not gzipped) and answers /token with the
    {"token": "<credential>"} JSON ("" when no -c), which is the backstop."""
    r = await _http_get_once(host, port, "/", timeout, tls)
    if not r:
        return None
    status, headers, body = r
    sig = (b"ttyd" in body.lower()
           or "ttyd" in headers.get("server", "").lower()
           or 'realm="ttyd"' in headers.get("www-authenticate", "").lower())
    if not sig:
        # /token returns a small {"token": "..."} JSON on an open ttyd; with -c
        # it is 401 too, so this backstop only fires for an unauthenticated one.
        r2 = await _http_get_once(host, port, "/token", timeout, tls)
        if not (r2 and r2[0] == 200 and b'"token"' in r2[2] and len(r2[2]) < 256):
            return None
    return {"auth": status in (401, 403)}


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


# ---------------------------------------------------------------------------
# SSDP / UPnP (UDP 1900). A unicast M-SEARCH (ssdp:all) makes a UPnP device
# answer with HTTP-over-UDP responses naming its SERVER string, the LOCATION of
# its device-description XML, and the ST/USN of each advertised target. UPnP
# discovery is unauthenticated BY DESIGN, so this is INFORMATIONAL device
# enumeration (model/firmware for CVE anchoring + advertised service surface),
# not an unauth-access breach. Unicast only -- never leaves the scanned host.
# ---------------------------------------------------------------------------
_SSDP_PORTS = {1900}
_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n"
    "USER-AGENT: servicescan UPnP/1.1\r\n\r\n"
).encode()


def _ssdp_headers(text: str) -> dict:
    """Parse an SSDP/HTTP response's headers into a lower-cased dict."""
    out = {}
    for ln in text.split("\r\n")[1:]:
        k, sep, v = ln.partition(":")
        if sep:
            out[k.strip().lower()] = v.strip()
    return out


def _ssdp_location_parts(location: str):
    """(path, port, tls) from a LOCATION URL, keeping the scanned host so the
    description fetch never pivots to an advertised LAN IP. None if unparseable."""
    m = re.match(r"(https?)://[^/:]+(?::(\d+))?(/[^\s]*)?$", location, re.I)
    if not m:
        return None
    tls = m.group(1).lower() == "https"
    port = int(m.group(2)) if m.group(2) else (443 if tls else 80)
    return (m.group(3) or "/"), port, tls


def _parse_upnp_desc(xml: str) -> dict:
    """Pull device identity + advertised serviceType list from a UPnP device
    description XML (regex, dependency-free)."""
    def grab(tag):
        m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.I | re.S)
        return " ".join(m.group(1).split()) if m else ""
    services = [" ".join(s.split())
                for s in re.findall(r"<serviceType>(.*?)</serviceType>",
                                    xml, re.I | re.S)]
    return {"friendly": grab("friendlyName"),
            "manufacturer": grab("manufacturer"),
            "model": grab("modelName"),
            "model_number": grab("modelNumber"),
            "device_type": grab("deviceType"),
            "services": services}


async def ssdp_probe(host: str, port: int, timeout: float) -> dict | None:
    """Unicast SSDP M-SEARCH (ssdp:all) over UDP. Collects the device's
    responses for a short window and aggregates SERVER / LOCATION / ST / USN.
    Returns {server, locations, sts, usns} or None when nothing answers."""
    loop = asyncio.get_event_loop()
    packets: list[bytes] = []

    class _P(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):  # noqa: ARG002
            packets.append(data)

        def error_received(self, exc):  # noqa: ARG002
            pass

    try:
        transport, _ = await asyncio.wait_for(
            loop.create_datagram_endpoint(_P, remote_addr=(host, port)),
            timeout=timeout)
    except Exception:  # noqa: BLE001
        return None
    try:
        transport.sendto(_SSDP_MSEARCH)
        await asyncio.sleep(min(timeout, 2.0))      # collect the response burst
    finally:
        transport.close()
    server, locations, sts, usns = "", [], [], []
    for p in packets:
        text = p.decode("latin-1", "replace")
        if not (text.upper().startswith("HTTP/") or text.upper().startswith("NOTIFY")):
            continue
        h = _ssdp_headers(text)
        if h.get("server") and not server:
            server = h["server"]
        for key, bucket in (("location", locations), ("st", sts), ("usn", usns)):
            v = h.get(key)
            if v and v not in bucket:
                bucket.append(v)
    if not (server or locations or sts):
        return None
    return {"server": server, "locations": locations, "sts": sts, "usns": usns}


async def ssdp_describe(host: str, location: str, timeout: float) -> dict:
    """Fetch and parse the UPnP device-description XML named by a LOCATION URL,
    read-only, keeping the scanned host (adopting only the URL's port/path/
    scheme). Returns a parsed dict, or {} on any failure."""
    parts = _ssdp_location_parts(location)
    if not parts:
        return {}
    path, dport, tls = parts
    r = await _http_get_once(host, dport, path, timeout, tls)
    if not r or r[0] != 200:
        return {}
    return _parse_upnp_desc(r[2].decode("latin-1", "replace"))


# ---------------------------------------------------------------------------
# SMB (TCP 445). Dependency-free, read-only posture for internal-network
# triage. Three facts recovered without credentials:
#   1. SMB signing posture (dialect SecurityMode): signing-not-required is the
#      precondition for NTLM relay (ntlmrelayx) -> alert.
#   2. SMBv1 enabled (a server that answers an SMB1 "NT LM 0.12" negotiate):
#      EternalBlue / wormable-RCE surface -> alert.
#   3. The NTLM CHALLENGE leaked by an anonymous SMB2 SESSION_SETUP, which
#      names the host OS build + AD/NetBIOS domain and computer names (one
#      unauthenticated packet) -> informational recon + CVE anchor.
# We send an NTLMSSP NEGOTIATE (type 1) and only READ the server's CHALLENGE
# (type 2); no credentials, no type-3, so no authentication is attempted.
# Wire format per MS-SMB2 (NEGOTIATE/SESSION_SETUP) and MS-NLMP (CHALLENGE).
# ---------------------------------------------------------------------------
_SMB_PORTS = {445}


def _nbss(msg: bytes) -> bytes:
    """Direct-TCP (NBSS) framing: 0x00 + 3-byte big-endian length + message."""
    return b"\x00" + len(msg).to_bytes(3, "big") + msg


def _smb2_header(command: int, msgid: int) -> bytes:
    return (b"\xfeSMB"                       # ProtocolId
            + (64).to_bytes(2, "little")     # StructureSize
            + b"\x00\x00"                     # CreditCharge
            + b"\x00\x00\x00\x00"             # Status (0 on request)
            + command.to_bytes(2, "little")   # Command
            + (1).to_bytes(2, "little")       # CreditRequest
            + b"\x00\x00\x00\x00"             # Flags
            + b"\x00\x00\x00\x00"             # NextCommand
            + msgid.to_bytes(8, "little")     # MessageId
            + b"\x00\x00\x00\x00"             # Reserved
            + b"\x00\x00\x00\x00"             # TreeId
            + b"\x00" * 8                     # SessionId
            + b"\x00" * 16)                   # Signature  (total 64)


_SMB2_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302)


def _smb2_negotiate_body() -> bytes:
    return ((36).to_bytes(2, "little")                   # StructureSize
            + len(_SMB2_DIALECTS).to_bytes(2, "little")  # DialectCount
            + (1).to_bytes(2, "little")                  # SecurityMode: SIGNING_ENABLED
            + b"\x00\x00"                                # Reserved
            + b"\x00\x00\x00\x00"                        # Capabilities
            + b"\x00" * 16                               # ClientGuid
            + b"\x00" * 8                                # ClientStartTime
            + b"".join(d.to_bytes(2, "little") for d in _SMB2_DIALECTS))


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _ntlm_type1() -> bytes:
    """NTLMSSP NEGOTIATE (type 1). Flags request Unicode + a server VERSION +
    TargetInfo so the CHALLENGE carries the OS build and AD/NetBIOS names."""
    flags = (0x00000001 | 0x00000004 | 0x00000200 | 0x00008000 | 0x00080000
             | 0x00800000 | 0x02000000 | 0x20000000 | 0x80000000)
    return (b"NTLMSSP\x00"
            + (1).to_bytes(4, "little")      # MessageType 1
            + flags.to_bytes(4, "little")
            + b"\x00" * 8                     # DomainNameFields
            + b"\x00" * 8                     # WorkstationFields
            + bytes([6, 1, 0, 0, 0, 0, 0, 15]))  # Version (any)


def _spnego_ntlm(token: bytes) -> bytes:
    """Wrap an NTLMSSP token in a GSS-API SPNEGO NegTokenInit."""
    ntlmssp_oid = bytes.fromhex("2b06010401823702020a")   # 1.3.6.1.4.1.311.2.2.10
    spnego_oid = bytes.fromhex("2b0601050502")            # 1.3.6.1.5.5.2
    mechtypes = _der(0x30, _der(0x06, ntlmssp_oid))
    inner = _der(0x30, _der(0xa0, mechtypes) + _der(0xa2, _der(0x04, token)))
    return _der(0x60, _der(0x06, spnego_oid) + _der(0xa0, inner))


def _smb2_session_setup_body() -> bytes:
    spnego = _spnego_ntlm(_ntlm_type1())
    return ((25).to_bytes(2, "little")       # StructureSize
            + b"\x00"                         # Flags
            + b"\x01"                         # SecurityMode: SIGNING_ENABLED
            + b"\x00\x00\x00\x00"             # Capabilities
            + b"\x00\x00\x00\x00"             # Channel
            + (88).to_bytes(2, "little")      # SecurityBufferOffset (64 hdr + 24)
            + len(spnego).to_bytes(2, "little")
            + b"\x00" * 8                     # PreviousSessionId
            + spnego)


def _smb1_negotiate() -> bytes:
    hdr = (b"\xffSMB" + b"\x72" + b"\x00\x00\x00\x00"     # ProtocolId + NEGOTIATE + Status
           + b"\x18" + b"\x01\x28"                         # Flags, Flags2
           + b"\x00" * 20)                                 # PIDHigh+Sig+Reserved+TID+PID+UID+MID
    dialects = b"\x02" + b"NT LM 0.12\x00"
    return hdr + b"\x00" + len(dialects).to_bytes(2, "little") + dialects


def _parse_ntlm_type2(data: bytes) -> dict:
    """Pull OS build + AD/NetBIOS names from an NTLMSSP CHALLENGE anywhere in
    `data` (the SESSION_SETUP response's SPNEGO buffer)."""
    i = data.find(b"NTLMSSP\x00\x02\x00\x00\x00")
    if i < 0:
        return {}
    msg = data[i:]
    if len(msg) < 48:
        return {}
    flags = int.from_bytes(msg[20:24], "little")
    ti_len = int.from_bytes(msg[40:42], "little")
    ti_off = int.from_bytes(msg[44:48], "little")
    info = {}
    if flags & 0x02000000 and len(msg) >= 56:            # NEGOTIATE_VERSION
        info["os"] = f"{msg[48]}.{msg[49]}.{int.from_bytes(msg[50:52], 'little')}"
    av = msg[ti_off:ti_off + ti_len]
    names = {1: "nb_computer", 2: "nb_domain", 3: "dns_computer",
             4: "dns_domain", 5: "dns_tree"}
    j = 0
    while j + 4 <= len(av):
        avid = int.from_bytes(av[j:j + 2], "little")
        avlen = int.from_bytes(av[j + 2:j + 4], "little")
        val = av[j + 4:j + 4 + avlen]
        j += 4 + avlen
        if avid == 0:
            break
        if avid in names:
            info[names[avid]] = val.decode("utf-16-le", "replace").rstrip("\x00")
    return info


async def _smb_recv(reader, timeout: float) -> bytes:
    """Read one NBSS-framed SMB message; b'' on EOF/short read."""
    try:
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout)
        n = int.from_bytes(hdr[1:4], "big")
        return await asyncio.wait_for(reader.readexactly(n), timeout)
    except Exception:  # noqa: BLE001
        return b""


async def smb_probe(host: str, port: int, timeout: float):
    """Returns {dialect, signing_required, signing_enabled, smbv1, ntlm} or None.
    Read-only: an anonymous SMB2 negotiate + session-setup (NTLM type-1 only)
    and a separate SMB1 negotiate; no credentials, no NTLM type-3."""
    info = {"dialect": None, "signing_required": None, "signing_enabled": None,
            "smbv1": False, "ntlm": {}}
    got_smb2 = False
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        try:
            writer.write(_nbss(_smb2_header(0x0000, 0) + _smb2_negotiate_body()))
            await writer.drain()
            resp = await _smb_recv(reader, timeout)
            if resp[:4] == b"\xfeSMB" and len(resp) >= 70:
                got_smb2 = True
                secmode = int.from_bytes(resp[66:68], "little")
                info["signing_enabled"] = bool(secmode & 0x01)
                info["signing_required"] = bool(secmode & 0x02)
                info["dialect"] = int.from_bytes(resp[68:70], "little")
                writer.write(_nbss(_smb2_header(0x0001, 1)
                                   + _smb2_session_setup_body()))
                await writer.drain()
                r2 = await _smb_recv(reader, timeout)
                if r2[:4] == b"\xfeSMB":
                    info["ntlm"] = _parse_ntlm_type2(r2)
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        try:
            writer.write(_nbss(_smb1_negotiate()))
            await writer.drain()
            r = await _smb_recv(reader, timeout)
            if r[:4] == b"\xffSMB":
                info["smbv1"] = True
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass
    if not got_smb2 and not info["smbv1"]:
        return None
    return info


# ---------------------------------------------------------------------------
# NTLM over HTTP (IIS/Exchange/RDWeb). Endpoints that offer `WWW-Authenticate:
# NTLM`/`Negotiate` leak the same host identity as SMB: a GET carrying only an
# NTLM NEGOTIATE (type 1) makes the server answer 401 with an NTLM CHALLENGE
# (type 2) naming the OS build + AD/NetBIOS domain and computer. No credentials
# are sent (no type 3), so no authentication is attempted -- informational
# recon that also anchors CVE correlation. Reuses the SMB NTLM primitives.
# ---------------------------------------------------------------------------
_HTTP_NTLM_PATHS = ("/ews/", "/rpc/", "/autodiscover/autodiscover.xml",
                    "/oab/", "/mapi/", "/powershell/", "/RDWeb/",
                    "/EWS/Exchange.asmx", "/aspnet_client/")


async def http_ntlm_probe(host: str, port: int, timeout: float, tls: bool):
    """Read an HTTP NTLM type-2 challenge (no credentials) to disclose OS build
    + AD/NetBIOS names. Returns (path, info) or None. Checks '/' first and only
    sweeps the IIS/Exchange paths when the server banner looks like Microsoft."""
    import base64

    async def challenge(path: str, wa: str):
        if "ntlm" in wa:
            auth = "NTLM " + base64.b64encode(_ntlm_type1()).decode()
        else:
            auth = "Negotiate " + base64.b64encode(
                _spnego_ntlm(_ntlm_type1())).decode()
        r2 = await _http_get_once(host, port, path, timeout, tls,
                                  extra_headers={"Authorization": auth})
        if not r2:
            return None
        m = re.search(r"(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]{16,})",
                      r2[1].get("www-authenticate", ""))
        if not m:
            return None
        try:
            blob = base64.b64decode(m.group(1))
        except Exception:  # noqa: BLE001
            return None
        info = _parse_ntlm_type2(blob)
        return (path, info) if info else None

    r = await _http_get_once(host, port, "/", timeout, tls)
    if not r:
        return None
    status, headers, _ = r
    wa = headers.get("www-authenticate", "").lower()
    if status == 401 and ("ntlm" in wa or "negotiate" in wa):
        res = await challenge("/", wa)
        if res:
            return res
    server = headers.get("server", "").lower()
    if not ("iis" in server or "microsoft" in server):
        return None
    for path in _HTTP_NTLM_PATHS:
        r = await _http_get_once(host, port, path, timeout, tls)
        if not r:
            continue
        st, h, _ = r
        w = h.get("www-authenticate", "").lower()
        if st == 401 and ("ntlm" in w or "negotiate" in w):
            res = await challenge(path, w)
            if res:
                return res
    return None


# ---------------------------------------------------------------------------
# WinRM / WS-Management (TCP 5985 plaintext, 5986 TLS; endpoint /wsman).
# Dependency-free, read-only posture -- NO credentials are ever transmitted:
#   * WS-Management Identify (MS-WSMV / DMTF DSP0226): an unauthenticated POST
#     carrying <wsmid:Identify/> is answered with an IdentifyResponse naming
#     ProductVendor + protocol/stack version. This confirms the service IS
#     WinRM and leaks the WSMan stack version unauthenticated (the OS build is
#     withheld -- zeroed -- in the unauthenticated response by design).
#   * Auth-scheme enumeration: an unauthenticated request to /wsman is refused
#     with 401 and ONE WWW-Authenticate header per offered scheme (Negotiate /
#     Kerberos / CredSSP / Basic / NTLM). http.sys emits a SEPARATE header line
#     per scheme, so the raw response is parsed here -- the shared dict parser
#     would keep only the last one.
#   * If Basic is offered over PLAINTEXT 5985 the listener accepts base64
#     (cleartext) credentials over an unencrypted channel: any on-path observer
#     captures them, and a valid WinRM credential grants remote PowerShell =
#     full host takeover. Default WinRM requires Negotiate + message encryption
#     and refuses Basic/AllowUnencrypted, so this is an explicit misconfig ->
#     ALERT. Basic over TLS (5986) is protected in transit -> informational.
#   * If Negotiate/NTLM is offered, the shared NTLM primitive is applied to
#     /wsman to read the type-2 challenge (OS build + AD/NetBIOS identity) with
#     no credentials -> informational host-identity leak.
# Sources: MS-WSMV; WS-Management (DMTF DSP0226/DSP0227); Microsoft WinRM docs
# (Identify request/response XML); RFC 7617 (Basic = base64, not encryption).
# ---------------------------------------------------------------------------
_WINRM_PORTS = {5985, 5986}
_WINRM_IDENTIFY = (
    b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    b'xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/'
    b'wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/>'
    b'</s:Body></s:Envelope>')


async def _winrm_request(host: str, port: int, timeout: float, tls: bool,
                         body: bytes, auth: str | None = None):
    """Raw HTTP/1.0 POST /wsman. Returns (status:int, headers:dict,
    www_authenticate:list[str], body:bytes) or None. Read-only; no redirects;
    TLS never verified. Preserves EVERY WWW-Authenticate header (one per offered
    scheme); other headers are first-wins."""
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
        extra = f"Authorization: {auth}\r\n" if auth else ""
        req = (f"POST /wsman HTTP/1.0\r\nHost: {host}:{port}\r\n"
               f"User-Agent: servicescan\r\n"
               f"Content-Type: application/soap+xml;charset=UTF-8\r\n"
               f"{extra}Content-Length: {len(body)}\r\n"
               f"Connection: close\r\n\r\n").encode() + body
        writer.write(req)
        await writer.drain()
        try:
            while len(raw) < 16384:
                chunk = await asyncio.wait_for(reader.read(16384), timeout=timeout)
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
    head, _, bdy = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    try:
        status = int(lines[0].split(b" ")[1])
    except (IndexError, ValueError):
        return None
    headers, www = {}, []
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        if not k:
            continue
        key = k.strip().lower().decode("latin-1", "replace")
        val = v.strip().decode("latin-1", "replace")
        if key == "www-authenticate":
            www.append(val)
        else:
            headers.setdefault(key, val)
    return status, headers, www, bdy


def _winrm_schemes(www_auth: list) -> list:
    """Ordered, de-duplicated auth schemes from the WWW-Authenticate header(s).
    The scheme is the leading token of each value (http.sys sends one per
    line, but a combined comma-separated value is handled too)."""
    out = []
    for v in www_auth:
        for part in v.split(","):
            tok = part.strip().split(" ", 1)[0].strip()
            if tok and tok not in out:
                out.append(tok)
    return out


def _parse_winrm_identify(body: bytes) -> dict:
    """ProductVendor / ProductVersion / ProtocolVersion out of an
    IdentifyResponse (namespace-prefix agnostic)."""
    text = body.decode("latin-1", "replace")
    info = {}
    for tag, key in (("ProductVendor", "vendor"),
                     ("ProductVersion", "product_version"),
                     ("ProtocolVersion", "protocol")):
        m = re.search(rf"<(?:\w+:)?{tag}>\s*(.*?)\s*</(?:\w+:)?{tag}>",
                      text, re.S)
        if m and m.group(1).strip():
            info[key] = " ".join(m.group(1).split())
    return info


async def winrm_probe(host: str, port: int, timeout: float, tls: bool):
    """Unauthenticated WinRM/WS-Management posture. Returns a dict
    {identify, schemes, server, ntlm} or None when the endpoint is not
    WS-Management. No credentials are ever sent."""
    import base64

    r = await _winrm_request(host, port, timeout, tls, _WINRM_IDENTIFY)
    if not r:
        return None
    status, headers, www, body = r
    ident = (_parse_winrm_identify(body)
             if status == 200 and b"IdentifyResponse" in body else {})
    schemes = _winrm_schemes(www) if status == 401 else []
    if not schemes:
        # Identify was answered (200) or refused without a challenge; force a
        # 401 with an unauthenticated empty request to read the offered schemes.
        r2 = await _winrm_request(host, port, timeout, tls, b"")
        if r2 and r2[0] == 401:
            schemes = _winrm_schemes(r2[2])
            if not headers.get("server"):
                headers = r2[1]

    server = headers.get("server", "")
    low = [s.lower() for s in schemes]
    is_wsman = (bool(ident) or "microsoft-httpapi" in server.lower()
                or any(s in ("negotiate", "kerberos", "credssp") for s in low))
    if not is_wsman:
        return None

    ntlm = {}
    if "negotiate" in low or "ntlm" in low:
        use_nego = "negotiate" in low
        token = _spnego_ntlm(_ntlm_type1()) if use_nego else _ntlm_type1()
        auth = ("Negotiate " if use_nego else "NTLM ") + \
            base64.b64encode(token).decode()
        rc = await _winrm_request(host, port, timeout, tls, b"", auth=auth)
        if rc and rc[2]:
            m = re.search(r"(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]{16,})",
                          " ".join(rc[2]))
            if m:
                try:
                    ntlm = _parse_ntlm_type2(base64.b64decode(m.group(1)))
                except Exception:  # noqa: BLE001
                    ntlm = {}
    return {"identify": ident, "schemes": schemes, "server": server,
            "ntlm": ntlm}


# ---------------------------------------------------------------------------
# Kerberos KDC (TCP 88). Dependency-free ASN.1/DER per RFC 4120. For each
# candidate principal an AS-REQ is sent with NO pre-authentication (no PA-DATA);
# the KDC's reply classifies the account WITHOUT sending any credential:
#   * KRB-ERROR KDC_ERR_PREAUTH_REQUIRED (25)  -> the user EXISTS (AD requires
#     pre-auth, so a known principal is asked for it)         [informational].
#   * KRB-ERROR KDC_ERR_C_PRINCIPAL_UNKNOWN (6) -> the user does not exist.
#   * an AS-REP (no error) -> the account EXISTS *and* has pre-auth DISABLED
#     (DONT_REQUIRE_PREAUTH): the KDC just handed out a reply whose enc-part is
#     encrypted with the account's key = an offline-crackable hash obtained with
#     no credentials ("AS-REP roasting")                              [ALERT].
# A realm is mandatory in the AS-REQ (supplied with --realm or derived from a
# dotted-FQDN target). Kerberos messages are explicitly application-tagged DER:
# AS-REQ=[APPLICATION 10]=0x6A, AS-REP=[APPLICATION 11]=0x6B,
# KRB-ERROR=[APPLICATION 30]=0x7E. Transport is TCP (4-byte length prefix).
# Nothing but the unauthenticated AS-REQ is ever sent. Wire format and error
# codes per RFC 4120 (section 5.4 KDC-REQ, 5.9.1 KRB-ERROR, 7.5.9 error table,
# 6.2 principal-name types); the AS-REP hash layout matches hashcat 18200 /
# impacket GetNPUsers.
# ---------------------------------------------------------------------------
_KRB_PORTS = {88}
_KRB_DEFAULT_USERS = ("administrator", "guest", "krbtgt", "svc-sql",
                      "svc-backup", "service", "backup")
# NT-PRINCIPAL = 1, NT-SRV-INST = 2 (RFC 4120 section 6.2).
# KDCOptions bits forwardable|proxiable|renewable (matches impacket's AS-REQ).
_KRB_KDC_OPTIONS = 0x40810010


def _looks_like_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _krb_principal(name_type: int, components: list) -> bytes:
    """PrincipalName ::= SEQUENCE { name-type [0] Int32,
    name-string [1] SEQUENCE OF KerberosString (GeneralString, tag 0x1B) }."""
    names = b"".join(_der(0x1B, c.encode()) for c in components)
    return _der(0x30, _der(0xA0, _ber_int(name_type))
                + _der(0xA1, _der(0x30, names)))


def _krb_as_req(user: str, realm: str) -> bytes:
    """AS-REQ ([APPLICATION 10]) with no PA-DATA (pre-auth omitted), cname=user,
    sname=krbtgt/REALM, etype preference RC4(23),AES256(18),AES128(17)."""
    nonce = int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
    body = _der(0x30,
        _der(0xA0, _der(0x03, b"\x00" + _KRB_KDC_OPTIONS.to_bytes(4, "big")))
        + _der(0xA1, _krb_principal(1, [user]))            # cname  [1] NT-PRINCIPAL
        + _der(0xA2, _der(0x1B, realm.encode()))           # realm  [2]
        + _der(0xA3, _krb_principal(2, ["krbtgt", realm]))  # sname [3] NT-SRV-INST
        + _der(0xA5, _der(0x18, b"20370913024805Z"))       # till   [5]
        + _der(0xA7, _ber_int(nonce))                      # nonce  [7]
        + _der(0xA8, _der(0x30, _ber_int(23) + _ber_int(18)
                          + _ber_int(17))))                # etype  [8]
    kdc_req = _der(0x30,
        _der(0xA1, _ber_int(5))        # pvno     [1] = 5
        + _der(0xA2, _ber_int(10))     # msg-type [2] = 10 (AS-REQ)
        + _der(0xA4, body))            # req-body [4]   (padata [3] omitted)
    return _der(0x6A, kdc_req)


def _krb_seq_fields(data: bytes) -> list:
    """Unwrap [APPLICATION n] -> SEQUENCE and return its context-tagged fields."""
    top = _ber_split(data)
    if not top:
        return []
    seq = _ber_split(top[0][1])        # the inner SEQUENCE TLV
    if not seq or seq[0][0] != 0x30:
        return []
    return _ber_split(seq[0][1])


def _krb_ctx_int(fields: list, ctx_tag: int):
    for t, c in fields:
        if t == ctx_tag:
            kids = _ber_split(c)
            if kids and kids[0][0] == 0x02:
                return int.from_bytes(kids[0][1], "big")
    return None


def _krb_ctx_str(fields: list, ctx_tag: int) -> str:
    for t, c in fields:
        if t == ctx_tag:
            kids = _ber_split(c)
            if kids:
                return kids[0][1].decode("latin-1", "replace")
    return ""


def _krb_asrep_hash(fields: list, user: str, realm: str) -> dict:
    """Pull EncryptedData (etype + cipher) from enc-part [6] of an AS-REP and,
    for RC4 (etype 23), format the hashcat-18200 $krb5asrep$ string."""
    out = {}
    for t, c in fields:
        if t != 0xA6:                  # enc-part [6] EncryptedData
            continue
        ed = _ber_split(c)
        if not ed or ed[0][0] != 0x30:
            return out
        edf = _ber_split(ed[0][1])
        etype = _krb_ctx_int(edf, 0xA0)
        cipher = b""
        for tt, cc in edf:
            if tt == 0xA2:             # cipher [2] OCTET STRING
                oc = _ber_split(cc)
                if oc and oc[0][0] == 0x04:
                    cipher = oc[0][1]
        out["etype"] = etype
        if etype == 23 and len(cipher) > 16:
            out["hash"] = (f"$krb5asrep$23${user}@{realm}:"
                           f"{cipher[:16].hex()}${cipher[16:].hex()}")
        elif cipher:
            out["cipher_len"] = len(cipher)
    return out


def _krb_parse(data: bytes, user: str, realm: str) -> dict:
    """Classify a KDC reply. kind in {'error','as-rep'}; errors carry 'error'."""
    if not data:
        return {}
    tag = data[0]
    fields = _krb_seq_fields(data)
    if tag == 0x7E:                    # KRB-ERROR
        return {"kind": "error", "error": _krb_ctx_int(fields, 0xA6),  # [6]
                "realm": _krb_ctx_str(fields, 0xA9)}                    # [9]
    if tag == 0x6B:                    # AS-REP
        return {"kind": "as-rep", "asrep": _krb_asrep_hash(fields, user, realm)}
    return {}


async def _krb_send(host: str, port: int, timeout: float, msg: bytes):
    """Send one Kerberos message over TCP (4-byte big-endian length prefix) and
    return the reply body, or None. Read-only exchange."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:  # noqa: BLE001
        return None
    try:
        writer.write(len(msg).to_bytes(4, "big") + msg)
        await writer.drain()
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        n = int.from_bytes(hdr, "big")
        if n <= 0 or n > 262144:
            return None
        return await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass


async def kerberos_probe(host: str, port: int, timeout: float, realm: str,
                         users=_KRB_DEFAULT_USERS):
    """Unauthenticated AS-REQ (no pre-auth) per candidate principal. Returns
    {realm, is_kdc, wrong_realm, valid[], unknown[], roastable[{user,etype,hash}]}
    or None when the port is not a KDC. No credentials are ever sent."""
    res = {"realm": realm, "is_kdc": False, "wrong_realm": False,
           "valid": [], "unknown": [], "roastable": []}
    for u in users:
        reply = await _krb_send(host, port, timeout, _krb_as_req(u, realm))
        if not reply:
            continue
        info = _krb_parse(reply, u, realm)
        if not info:
            continue
        res["is_kdc"] = True
        if info["kind"] == "as-rep":
            res["valid"].append(u)
            res["roastable"].append({"user": u,
                                     "etype": info["asrep"].get("etype"),
                                     "hash": info["asrep"].get("hash")})
        elif info["kind"] == "error":
            e = info.get("error")
            if e == 25:                # KDC_ERR_PREAUTH_REQUIRED -> exists
                res["valid"].append(u)
            elif e == 6:               # KDC_ERR_C_PRINCIPAL_UNKNOWN -> absent
                res["unknown"].append(u)
            elif e == 68:              # KDC_ERR_WRONG_REALM
                res["wrong_realm"] = True
                if info.get("realm"):
                    res["realm_hint"] = info["realm"]
                break                  # wrong realm -> every reply is the same
    return res if res["is_kdc"] else None


# ---------------------------------------------------------------------------
# NFS / rpcbind (TCP 111). Dependency-free ONC RPC: a portmap DUMP (proc 4)
# enumerates the registered RPC programs, and if mountd (100005) is present its
# EXPORT (proc 5) lists the NFS exports and the hosts each is shared with. An
# export shared with everyone (empty group list, or "*") is reachable by any
# client -> read (and, with no_root_squash, write) of the server's files = an
# unauthenticated data-exposure alert. All calls are read-only (DUMP/EXPORT
# query procedures; nothing is mounted). Wire format per RFC 1833 (rpcbind),
# RFC 5531 (RPC) and RFC 1813 Appendix I (MOUNT v3).
# ---------------------------------------------------------------------------
_NFS_PORTS = {111}
_RPC_PROG_NAMES = {100000: "portmapper", 100003: "nfs", 100005: "mountd",
                   100021: "nlockmgr", 100024: "status", 100227: "nfs_acl",
                   100005: "mountd", 100011: "rquotad", 100009: "yppasswdd"}


def _rpc_call(xid: int, prog: int, vers: int, proc: int, args: bytes = b"") -> bytes:
    return (xid.to_bytes(4, "big") + (0).to_bytes(4, "big")      # mtype CALL
            + (2).to_bytes(4, "big")                             # rpcvers 2
            + prog.to_bytes(4, "big") + vers.to_bytes(4, "big")
            + proc.to_bytes(4, "big")
            + b"\x00" * 8 + b"\x00" * 8                          # AUTH_NULL cred+verf
            + args)


async def _rpc_roundtrip(host: str, port: int, call: bytes, timeout: float) -> bytes:
    """Send one record-marked RPC call over TCP, return the reply body (b'')."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:  # noqa: BLE001
        return b""
    try:
        writer.write((0x80000000 | len(call)).to_bytes(4, "big") + call)
        await writer.drain()
        mark = await asyncio.wait_for(reader.readexactly(4), timeout)
        n = int.from_bytes(mark, "big") & 0x7fffffff
        return await asyncio.wait_for(reader.readexactly(n), timeout)
    except Exception:  # noqa: BLE001
        return b""
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:  # noqa: BLE001
            pass


def _rpc_results_offset(msg: bytes):
    """(accepted, offset) of the procedure results in an RPC reply, or
    (False, 0). Handles the AUTH_NULL verifier length generically."""
    if len(msg) < 20:
        return False, 0
    if int.from_bytes(msg[4:8], "big") != 1:          # REPLY
        return False, 0
    if int.from_bytes(msg[8:12], "big") != 0:         # MSG_ACCEPTED
        return False, 0
    vlen = int.from_bytes(msg[16:20], "big")
    off = 20 + vlen + ((4 - vlen % 4) % 4)
    if off + 4 > len(msg):
        return False, 0
    return int.from_bytes(msg[off:off + 4], "big") == 0, off + 4


def _xdr_str(data: bytes, i: int):
    n = int.from_bytes(data[i:i + 4], "big")
    i += 4
    s = data[i:i + n]
    i += n + ((4 - n % 4) % 4)
    return s.decode("latin-1", "replace"), i


def _parse_rpcb_dump(data: bytes, i: int):
    """portmap PMAPPROC_DUMP result: linked list of {prog,vers,prot,port}."""
    out = []
    while i + 4 <= len(data):
        if int.from_bytes(data[i:i + 4], "big") == 0:
            break
        i += 4
        if i + 16 > len(data):
            break
        out.append((int.from_bytes(data[i:i + 4], "big"),
                    int.from_bytes(data[i + 4:i + 8], "big"),
                    int.from_bytes(data[i + 8:i + 12], "big"),
                    int.from_bytes(data[i + 12:i + 16], "big")))
        i += 16
    return out


def _parse_mount_exports(data: bytes, i: int):
    """MOUNTPROC_EXPORT result: linked list of {dirpath, groups[]}."""
    exports = []
    while i + 4 <= len(data):
        if int.from_bytes(data[i:i + 4], "big") == 0:
            break
        i += 4
        dirp, i = _xdr_str(data, i)
        groups = []
        while i + 4 <= len(data):
            if int.from_bytes(data[i:i + 4], "big") == 0:
                i += 4
                break
            i += 4
            g, i = _xdr_str(data, i)
            groups.append(g)
        exports.append((dirp, groups))
    return exports


async def nfs_probe(host: str, port: int, timeout: float):
    """rpcbind DUMP + mountd EXPORT. Returns {programs, exports} or None.
    programs = [(prog,vers,prot,port)]; exports = [(dirpath, [groups])]."""
    dump = await _rpc_roundtrip(host, port, _rpc_call(1, 100000, 2, 4), timeout)
    ok, off = _rpc_results_offset(dump)
    if not ok:
        return None
    programs = _parse_rpcb_dump(dump, off)
    if not programs:
        return None
    # mountd (100005) TCP port, highest version available
    mountd = sorted([(v, pt) for (pg, v, pr, pt) in programs
                     if pg == 100005 and pr == 6 and pt], reverse=True)
    exports = []
    if mountd:
        mver, mport = mountd[0]
        ex = await _rpc_roundtrip(host, mport,
                                  _rpc_call(2, 100005, mver, 5), timeout)
        eok, eoff = _rpc_results_offset(ex)
        if eok:
            exports = _parse_mount_exports(ex, eoff)
    return {"programs": programs, "exports": exports}


# ---------------------------------------------------------------------------
# LDAP (TCP 389, 636 over TLS). Dependency-free BER (reusing the SNMP encoders).
# An anonymous simple bind (empty DN + empty password) that succeeds, followed
# by a rootDSE read, is standard AD recon: it names the directory's naming
# contexts (the domain DN), the DC hostname, and the forest/domain functional
# levels -- informational. The alert is when an anonymous subtree search of a
# naming context actually returns directory objects: anonymous directory reads
# are enabled, so anyone can enumerate users/computers without credentials.
# All operations are reads (bind + search); nothing is written. Wire per
# RFC 4511 (LDAPv3).
# ---------------------------------------------------------------------------
_LDAP_PORTS = {389}
_LDAPS_PORTS = {636}
_ROOTDSE_ATTRS = ("namingContexts", "defaultNamingContext", "dnsHostName",
                  "serverName", "domainFunctionality", "forestFunctionality",
                  "domainControllerFunctionality", "supportedLDAPVersion",
                  "rootDomainNamingContext", "vendorName", "vendorVersion")


def _ldap_bind_anon(msgid: int = 1) -> bytes:
    bind = _ber_int(3) + _ber_tlv(0x04, b"") + _ber_tlv(0x80, b"")  # v3, "", simple ""
    return _ber_tlv(0x30, _ber_int(msgid) + _ber_tlv(0x60, bind))


def _ldap_search(msgid: int, base: bytes, scope: int, attrs, sizelimit: int) -> bytes:
    body = (_ber_tlv(0x04, base)
            + _ber_tlv(0x0a, bytes([scope]))     # scope: 0 base, 1 one, 2 subtree
            + _ber_tlv(0x0a, b"\x00")            # derefAliases: never
            + _ber_int(sizelimit)
            + _ber_int(5)                        # timeLimit 5s
            + _ber_tlv(0x01, b"\x00")            # typesOnly false
            + _ber_tlv(0x87, b"objectClass")     # filter: present (objectClass=*)
            + _ber_tlv(0x30, b"".join(_ber_tlv(0x04, a.encode()) for a in attrs)))
    return _ber_tlv(0x30, _ber_int(msgid) + _ber_tlv(0x63, body))


async def _ldap_read_msg(reader, timeout: float):
    """Read one LDAPMessage (BER SEQUENCE). Returns (protocol_op_tag, op_bytes,
    msg_content) or (None, b'', b'')."""
    try:
        hdr = await asyncio.wait_for(reader.readexactly(2), timeout)
        if hdr[0] != 0x30:
            return None, b"", b""
        l = hdr[1]
        if l & 0x80:
            ext = await asyncio.wait_for(reader.readexactly(l & 0x7f), timeout)
            l = int.from_bytes(ext, "big")
        content = await asyncio.wait_for(reader.readexactly(l), timeout)
    except Exception:  # noqa: BLE001
        return None, b"", b""
    kids = _ber_split(content)
    if len(kids) < 2:
        return None, b"", content
    return kids[1][0], kids[1][1], content


def _parse_ldap_entry(op: bytes) -> dict:
    """SearchResultEntry -> {attrType: [values]} (objectName ignored)."""
    kids = _ber_split(op)
    out = {}
    if len(kids) < 2:
        return out
    for _, attr in _ber_split(kids[1][1]):            # PartialAttributeList
        ak = _ber_split(attr)
        if len(ak) < 2:
            continue
        atype = ak[0][1].decode("latin-1", "replace")
        vals = [v.decode("latin-1", "replace") for _, v in _ber_split(ak[1][1])]
        out[atype] = vals
    return out


async def ldap_probe(host: str, port: int, timeout: float, tls: bool):
    """Anonymous LDAP bind + rootDSE + a naming-context read probe. Returns
    {anon_bind, rootdse:{attr:[vals]}, anon_read:bool} or None (not LDAP)."""
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
    try:
        writer.write(_ldap_bind_anon(1))
        await writer.drain()
        tag, op, _ = await _ldap_read_msg(reader, timeout)
        if tag != 0x61:                               # not a BindResponse
            return None
        rc = _ber_split(op)
        bind_ok = bool(rc and rc[0][1] and rc[0][1][0] == 0)
        if not bind_ok:
            return {"anon_bind": False, "rootdse": {}, "anon_read": False}
        # rootDSE (base-object search)
        writer.write(_ldap_search(2, b"", 0, _ROOTDSE_ATTRS, 0))
        await writer.drain()
        rootdse = {}
        for _ in range(8):
            t, o, _c = await _ldap_read_msg(reader, timeout)
            if t == 0x64:
                rootdse.update(_parse_ldap_entry(o))
            elif t == 0x65 or t is None:              # SearchResultDone / EOF
                break
        # anonymous directory read? one-level search of a naming context
        nc = rootdse.get("defaultNamingContext") or rootdse.get("namingContexts")
        anon_read = False
        if nc:
            base = (nc[0] if isinstance(nc, list) else nc).encode()
            writer.write(_ldap_search(3, base, 1, (), 3))
            await writer.drain()
            for _ in range(8):
                t, o, _c = await _ldap_read_msg(reader, timeout)
                if t == 0x64:
                    anon_read = True
                elif t == 0x65 or t is None:
                    break
        return {"anon_bind": True, "rootdse": rootdse, "anon_read": anon_read}
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# rsync daemon (TCP 873). The daemon greets with "@RSYNCD: <ver>"; after echoing
# a version, an empty module request returns the module listing (each
# "name<TAB>comment"), ending with "@RSYNCD: EXIT". Selecting a module then
# answers "@RSYNCD: AUTHREQD <salt>" (auth required) or "@RSYNCD: OK" (no auth =
# anonymous access -> the module's files are reachable without credentials).
# We negotiate protocol 29 (so no digest-list is required) and never send rsync
# options after OK, so no file transfer occurs. Wire per rsync csprotocol.txt.
# ---------------------------------------------------------------------------
_RSYNC_PORTS = {873}


async def _rsync_line(reader, timeout: float):
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\n"), timeout)
        return data.rstrip(b"\r\n")
    except Exception:  # noqa: BLE001
        return None


async def rsync_probe(host: str, port: int, timeout: float):
    """List an rsync daemon's modules and test whether the first module accepts
    a connection without authentication. Returns {modules, first_module,
    first_auth} or None (not an rsync daemon)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:  # noqa: BLE001
        return None
    modules = []
    try:
        greet = await _rsync_line(reader, timeout)
        if not greet or not greet.startswith(b"@RSYNCD:"):
            return None
        writer.write(b"@RSYNCD: 29\n")
        await writer.drain()
        writer.write(b"\n")                       # empty module => list request
        await writer.drain()
        for _ in range(200):
            line = await _rsync_line(reader, timeout)
            if line is None:
                break
            if line.startswith(b"@RSYNCD:"):
                if b"EXIT" in line:
                    break
                continue
            s = line.decode("latin-1", "replace")
            if not s.strip():
                continue
            name, _, comment = s.partition("\t")
            modules.append((name.strip(), comment.strip()))
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:  # noqa: BLE001
            pass
    if not modules:
        return None

    first_auth = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        try:
            greet = await _rsync_line(reader, timeout)
            if greet and greet.startswith(b"@RSYNCD:"):
                writer.write(b"@RSYNCD: 29\n")
                await writer.drain()
                writer.write(modules[0][0].encode("latin-1", "replace") + b"\n")
                await writer.drain()
                for _ in range(5):
                    line = await _rsync_line(reader, timeout)
                    if line is None:
                        break
                    if line.startswith(b"@RSYNCD: OK"):
                        first_auth = False
                        break
                    if line.startswith(b"@RSYNCD: AUTHREQD"):
                        first_auth = True
                        break
                    if line.startswith(b"@RSYNCD: EXIT") or b"ERROR" in line:
                        break
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass
    return {"modules": modules, "first_module": modules[0][0],
            "first_auth": first_auth}


# ---------------------------------------------------------------------------
# gRPC (HTTP/2). Modern device/service control planes expose gRPC; nmap usually
# leaves these ports unidentified ("tcpwrapped"). Detection is dependency-free:
# over TLS we offer ALPN and check for a negotiated "h2"; cleartext we send the
# HTTP/2 connection preface and look for a SETTINGS frame (h2c). The real prize
# is server reflection -- an unauthenticated client can enumerate every service
# and method (the gRPC analogue of an open Swagger). Reflection list_services is
# done NATIVELY with no dependency: the service names ride in the response DATA
# frame (protobuf), not the HPACK headers, so we only need HPACK *encoding*
# (literals, no Huffman) for the request plus a tiny protobuf reader -- no HPACK
# decode, no grpc library. grpcurl / grpcio are used only as an optional fallback
# when the native client can't complete the exchange. Scoped to common gRPC ports
# / `grpc`-named services so HTTPS/2 web ports are never mislabelled.
# ---------------------------------------------------------------------------
_GRPC_PORTS = {50051, 6565, 9090, 8980, 9000, 7070}
_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _h2_frame(ftype: int, stream: int, payload: bytes = b"",
              flags: int = 0) -> bytes:
    return (len(payload).to_bytes(3, "big") + bytes([ftype, flags])
            + (stream & 0x7FFFFFFF).to_bytes(4, "big") + payload)


def _is_h2_settings(data: bytes) -> bool:
    """True if the bytes begin with an HTTP/2 SETTINGS frame on stream 0."""
    return (len(data) >= 9 and data[3] == 0x04
            and int.from_bytes(data[5:9], "big") & 0x7FFFFFFF == 0)


async def _grpc_h2c_detect(host: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except Exception:  # noqa: BLE001
        return False
    try:
        writer.write(_H2_PREFACE + _h2_frame(0x04, 0))   # preface + empty SETTINGS
        await writer.drain()
        data = b""
        while len(data) < 9:
            chunk = await asyncio.wait_for(reader.read(64), timeout=timeout)
            if not chunk:
                break
            data += chunk
        return _is_h2_settings(data)
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass


async def _grpc_h2_alpn_detect(host: str, port: int, timeout: float) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:  # noqa: BLE001
        pass
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
    except Exception:  # noqa: BLE001
        return False
    try:
        sslobj = writer.get_extra_info("ssl_object")
        return bool(sslobj) and sslobj.selected_alpn_protocol() == "h2"
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass


async def grpc_probe(host: str, port: int, timeout: float,
                     tls: bool) -> dict | None:
    """Dependency-free HTTP/2 detection. None if the port is not HTTP/2, else
    {transport}. TLS uses ALPN; cleartext uses the h2c preface."""
    if tls:
        return {"transport": "h2 (ALPN, TLS)"} if await _grpc_h2_alpn_detect(
            host, port, timeout) else None
    return {"transport": "h2c (cleartext)"} if await _grpc_h2c_detect(
        host, port, timeout) else None


# --- native reflection (dependency-free) ---------------------------------
_REFLECT_PATHS = (
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
)
# gRPC-framed ServerReflectionRequest{ list_services: "*" }: flag(0) + len(3) +
# protobuf field 7 (list_services, wiretype 2) len 1 "*"
_GRPC_REFLECT_MSG = b"\x00\x00\x00\x00\x03\x3a\x01\x2a"


def _hpack_int(value: int, prefix_bits: int) -> bytes:
    cap = (1 << prefix_bits) - 1
    if value < cap:
        return bytes([value])
    out = bytearray([cap])
    value -= cap
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _hpack_literal(name: str, val: str) -> bytes:
    """One header as 'literal without indexing, new name' (0x00), no Huffman."""
    n, v = name.encode(), val.encode()
    return (b"\x00" + _hpack_int(len(n), 7) + n
            + _hpack_int(len(v), 7) + v)


def _hpack_request(host: str, port: int, path: str, tls: bool) -> bytes:
    hdrs = [(":method", "POST"), (":scheme", "https" if tls else "http"),
            (":path", path), (":authority", f"{host}:{port}"),
            ("te", "trailers"), ("content-type", "application/grpc"),
            ("user-agent", "servicescan"), ("grpc-accept-encoding", "identity")]
    return b"".join(_hpack_literal(k, v) for k, v in hdrs)


def _varint(buf: bytes, i: int):
    shift = result = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, i


def _pb_fields(buf: bytes):
    """Yield (field_number, wiretype, value) for a protobuf message. value is an
    int for varint/fixed, bytes for length-delimited."""
    i, n = 0, len(buf)
    while i < n:
        tag, i = _varint(buf, i)
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = _varint(buf, i)
            yield fn, wt, v
        elif wt == 2:
            ln, i = _varint(buf, i)
            yield fn, wt, buf[i:i + ln]
            i += ln
        elif wt == 5:
            yield fn, wt, buf[i:i + 4]
            i += 4
        elif wt == 1:
            yield fn, wt, buf[i:i + 8]
            i += 8
        else:
            break


def _reflection_names(msg: bytes) -> list[str]:
    """ServerReflectionResponse(6=ListServiceResponse) -> repeated 1=ServiceResponse
    -> 1=name (string)."""
    names = []
    for fn, wt, val in _pb_fields(msg):
        if fn == 6 and wt == 2:
            for fn2, wt2, val2 in _pb_fields(val):
                if fn2 == 1 and wt2 == 2:
                    for fn3, wt3, val3 in _pb_fields(val2):
                        if fn3 == 1 and wt3 == 2:
                            names.append(val3.decode("utf-8", "replace"))
    return names


def _parse_reflection_services(data: bytes) -> list[str]:
    """Strip the gRPC length-prefix(es) off the DATA stream and pull the service
    names out of the protobuf message(s)."""
    names, i = [], 0
    while i + 5 <= len(data):
        mlen = int.from_bytes(data[i + 1:i + 5], "big")
        msg = data[i + 5:i + 5 + mlen]
        if len(msg) < mlen:
            break
        names += _reflection_names(msg)
        i += 5 + mlen
    # de-dup, keep order
    seen, out = set(), []
    for nm in names:
        if nm and nm not in seen:
            seen.add(nm)
            out.append(nm)
    return out


def _pb_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def _grpc_symbol_msg(symbol: str) -> bytes:
    """gRPC-framed ServerReflectionRequest{ file_containing_symbol: <symbol> }
    (field 4, wiretype 2) -- asks the server for the descriptor that defines a
    given service, which carries its methods."""
    s = symbol.encode()
    inner = b"\x22" + _pb_varint(len(s)) + s          # tag (4<<3)|2 = 0x22
    return b"\x00" + len(inner).to_bytes(4, "big") + inner


def _parse_fdp_services(fdp: bytes) -> dict:
    """FileDescriptorProto -> {full_service_name: [method_name, ...]}. Fields:
    2=package, 6=repeated ServiceDescriptorProto; service 1=name, 2=repeated
    MethodDescriptorProto; method 1=name."""
    pkg, raw = "", []
    for fn, wt, val in _pb_fields(fdp):
        if fn == 2 and wt == 2:
            pkg = val.decode("utf-8", "replace")
        elif fn == 6 and wt == 2:
            sname, methods = "", []
            for f2, w2, v2 in _pb_fields(val):
                if f2 == 1 and w2 == 2:
                    sname = v2.decode("utf-8", "replace")
                elif f2 == 2 and w2 == 2:
                    for f3, w3, v3 in _pb_fields(v2):
                        if f3 == 1 and w3 == 2:
                            methods.append(v3.decode("utf-8", "replace"))
            if sname:
                raw.append((sname, methods))
    return {f"{pkg}.{s}" if pkg else s: m for s, m in raw}


def _parse_reflection_file_response(data: bytes) -> dict:
    """Strip gRPC frame(s) and merge the service->methods map out of every
    ServerReflectionResponse (field 4 = FileDescriptorResponse, whose field 1 is
    a repeated bytes file_descriptor_proto)."""
    out, i = {}, 0
    while i + 5 <= len(data):
        mlen = int.from_bytes(data[i + 1:i + 5], "big")
        msg = data[i + 5:i + 5 + mlen]
        if len(msg) < mlen:
            break
        for fn, wt, val in _pb_fields(msg):
            if fn == 4 and wt == 2:
                for f2, w2, v2 in _pb_fields(val):
                    if f2 == 1 and w2 == 2:
                        for name, methods in _parse_fdp_services(v2).items():
                            dst = out.setdefault(name, [])
                            for m in methods:
                                if m not in dst:
                                    dst.append(m)
        i += 5 + mlen
    return out


async def _reflect_once(host: str, port: int, timeout: float, tls: bool,
                        path: str, req_msg: bytes = _GRPC_REFLECT_MSG):
    """One HTTP/2 reflection exchange on a fresh connection. Sends `req_msg`
    (default: list_services) and returns (spoke_grpc, raw_data_payload); the
    caller parses the payload for service names or file descriptors."""
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["h2"])
        except Exception:  # noqa: BLE001
            pass
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
    except Exception:  # noqa: BLE001
        return False, []

    def _safe_write(b):
        try:
            writer.write(b)
        except Exception:  # noqa: BLE001
            pass

    spoke = False
    data_payload = b""
    try:
        _safe_write(_H2_PREFACE + _h2_frame(0x04, 0))              # preface+SETTINGS
        _safe_write(_h2_frame(0x01, 1, _hpack_request(host, port, path, tls),
                              flags=0x04))                          # HEADERS END_HEADERS
        _safe_write(_h2_frame(0x00, 1, req_msg, flags=0x01))      # DATA END_STREAM
        try:
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        buf = b""
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 9:
                flen = int.from_bytes(buf[0:3], "big")
                if len(buf) < 9 + flen:
                    break
                ftype, fflags = buf[3], buf[4]
                fstream = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
                payload = buf[9:9 + flen]
                buf = buf[9 + flen:]
                if ftype == 0x04 and not (fflags & 0x01):          # SETTINGS -> ACK
                    _safe_write(_h2_frame(0x04, 0, flags=0x01))
                elif ftype == 0x06 and not (fflags & 0x01):        # PING -> ACK
                    _safe_write(_h2_frame(0x06, 0, payload, flags=0x01))
                elif ftype == 0x00 and fstream == 1:               # DATA
                    spoke = True
                    data_payload += payload
                    if fflags & 0x01:                              # END_STREAM
                        return True, data_payload
                elif ftype == 0x01 and fstream == 1:               # HEADERS / trailers
                    spoke = True
                    if fflags & 0x01:
                        return True, data_payload
                elif ftype == 0x07:                                # GOAWAY
                    return spoke, data_payload
            try:
                await writer.drain()
            except Exception:  # noqa: BLE001
                pass
        return spoke, data_payload
    except Exception:  # noqa: BLE001
        return spoke, data_payload
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass


async def grpc_reflect_native(host: str, port: int, timeout: float,
                              tls: bool):
    """Native gRPC server-reflection list_services. Returns (spoke_grpc,
    services). spoke_grpc=False => the port did not complete a gRPC reflection
    exchange; (True, []) => reflection is disabled/auth-gated."""
    spoke_any = False
    for path in _REFLECT_PATHS:
        spoke, payload = await _reflect_once(host, port, timeout, tls, path)
        svcs = _parse_reflection_services(payload)
        if spoke and svcs:
            return True, svcs
        spoke_any = spoke_any or spoke
    return spoke_any, []


async def grpc_reflect_methods_native(host: str, port: int, timeout: float,
                                      tls: bool, services: list,
                                      max_services: int = 10) -> dict:
    """Fetch per-service method descriptors via reflection file_containing_symbol
    (native, dependency-free). Returns {full_service_name: [method, ...]}; empty
    when the server doesn't return descriptors. Bounded to `max_services` symbols
    so a huge surface can't fan out into unbounded connections."""
    out: dict = {}
    for sym in services[:max_services]:
        for path in _REFLECT_PATHS:
            spoke, payload = await _reflect_once(host, port, timeout, tls, path,
                                                 _grpc_symbol_msg(sym))
            if spoke and payload:
                fr = _parse_reflection_file_response(payload)
                if fr:
                    for name, methods in fr.items():
                        dst = out.setdefault(name, [])
                        for m in methods:
                            if m not in dst:
                                dst.append(m)
                    break          # got this symbol's descriptors; next service
    return out


def _parse_grpcurl_list(text: str) -> list[str]:
    """Service names from `grpcurl ... list` stdout (one dotted name per line)."""
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if ln and "." in ln and " " not in ln and "\t" not in ln:
            out.append(ln)
    return out


async def _grpc_list_via_grpcio(host: str, port: int, timeout: float,
                                tls: bool):
    try:
        import grpc
        from grpc_reflection.v1alpha.proto_reflection_descriptor_database \
            import ProtoReflectionDescriptorDatabase
    except Exception:  # noqa: BLE001
        return None

    def blocking():
        target = f"{host}:{port}"
        channel = (grpc.secure_channel(target, grpc.ssl_channel_credentials())
                   if tls else grpc.insecure_channel(target))
        try:
            return list(ProtoReflectionDescriptorDatabase(channel).get_services())
        finally:
            channel.close()

    loop = asyncio.get_event_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(None, blocking), timeout=timeout + 2)


async def grpc_list_services(host: str, port: int, timeout: float,
                             tls: bool) -> dict | None:
    """Enumerate gRPC services via reflection. Native first (no dependency); if
    the native client completed a gRPC exchange its answer is authoritative
    ({tool: native, services}, services empty = reflection off/auth). Only when
    the native client could not speak gRPC at all do we fall back to grpcurl /
    grpcio, returning None if neither is installed. Read-only (list only)."""
    spoke, svcs = await grpc_reflect_native(host, port, timeout, tls)
    if spoke:
        return {"tool": "native", "services": svcs}

    import shutil
    gc = shutil.which("grpcurl")
    if gc:
        args = [gc, "-max-time", str(max(1, int(timeout))),
                "-insecure" if tls else "-plaintext", f"{host}:{port}", "list"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            out, _err = await asyncio.wait_for(proc.communicate(),
                                               timeout=timeout + 2)
        except Exception:  # noqa: BLE001
            return {"tool": "grpcurl", "services": []}
        return {"tool": "grpcurl",
                "services": _parse_grpcurl_list(out.decode("utf-8", "replace"))}
    try:
        svcs = await _grpc_list_via_grpcio(host, port, timeout, tls)
    except Exception:  # noqa: BLE001
        return {"tool": "grpcio", "services": []}
    return {"tool": "grpcio", "services": svcs} if svcs is not None else None


# script ids that mark a confirmed unauthenticated/anonymous exposure (critical)
EXPOSURE_ALERT_IDS = {"redis-unauth", "memcached-unauth", "mongodb-unauth",
                      "elasticsearch-unauth", "couchdb-unauth",
                      "docker-api-unauth", "etcd-unauth", "kubelet-anon",
                      "rtsp-unauth", "rtsp-default-creds",
                      "onvif-unauth", "onvif-default-creds",
                      "camera-snapshot-unauth",
                      "cam-cgi-unauth", "cam-cgi-default-creds",
                      "grpc-reflection-exposed", "snmp-unauth",
                      "ipmi-cipher-zero",
                      "prometheus-unauth", "consul-unauth", "rabbitmq-unauth",
                      "minio-unauth", "portainer-unauth", "zookeeper-unauth",
                      "camera-ws-stream-unauth", "ttyd-shell-unauth",
                      "mqtt-unauth", "smbv1-enabled", "smb-signing-not-required",
                      "nfs-export-world", "ldap-anonymous-read",
                      "rsync-anon-module", "winrm-basic-cleartext",
                      "krb-asrep-roastable", "postgres-trust-unauth"}


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

    if "postgres" in name or port in _POSTGRES_PORTS:
        res = await postgres_probe(host, port, cfg.timeout)
        if res:
            auth = res.get("auth")
            ver = res.get("version", "")
            if not svc.name:
                svc.name = "postgresql"
            if not svc.product:
                svc.product = "PostgreSQL"
            if ver and not svc.version:
                svc.version = ver
                svc.cve_skip = False
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            if auth == "trust":
                svc.confidence = "high"
                svc.extrainfo = "UNAUTHENTICATED access"
                svc.scripts.append({"id": "postgres-trust-unauth", "output":
                    "PostgreSQL accepted a connection WITHOUT any password "
                    "(pg_hba.conf `trust` auth -> AuthenticationOk"
                    + (f", server_version {ver}" if ver else "") + "). Any "
                    "client that can reach the port gets a full read/write "
                    "session and, via COPY/large-objects or an untrusted PL, "
                    "often code execution on the host. Replace `trust` with "
                    "scram-sha-256 in pg_hba.conf, bind to localhost, firewall "
                    f"{port}. (No query was issued; the session was dropped at "
                    "AuthenticationOk.)"})
            else:
                note = {"password": "cleartext password", "md5": "MD5",
                        "scram": "SCRAM-SHA-256", "kerberos": "Kerberos/GSSAPI",
                        "gss": "GSSAPI", "sspi": "SSPI"}.get(auth, auth)
                extra = ""
                if auth == "password":
                    extra = (" -- cleartext: credentials would transit "
                             "unencrypted without TLS")
                svc.scripts.append({"id": "postgres-auth", "output":
                    f"PostgreSQL requires authentication ({note}{extra}); the "
                    "unauthenticated StartupMessage was refused"
                    + (f" [{res['sqlstate']}]" if res.get("sqlstate") else "")
                    + ". Good posture."})
        return

    if "mysql" in name or "mariadb" in name or port in _MYSQL_PORTS:
        res = await mysql_probe(host, port, cfg.timeout)
        if res:
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            if res.get("err"):
                if not svc.name:
                    svc.name = "mysql"
                svc.scripts.append({"id": "mysql-info", "output":
                    "MySQL/MariaDB present but refused the connection by policy: "
                    + res["err"] + " (no authentication attempted)."})
            elif res.get("version"):
                ver = res["version"]
                # MariaDB 10.x advertises a legacy "5.5.5-" prefix; the real
                # version follows it.
                disp = ver[6:] if ver.startswith("5.5.5-") else ver
                is_maria = "mariadb" in ver.lower()
                if not svc.name:
                    svc.name = "mysql"
                if not svc.product:
                    svc.product = "MariaDB" if is_maria else "MySQL"
                if not svc.version:
                    svc.version = disp
                    svc.cve_skip = False
                if res.get("tls") is True:
                    tlsnote = "advertises TLS (CLIENT_SSL)"
                elif res.get("tls") is False:
                    tlsnote = ("does NOT advertise TLS (CLIENT_SSL) -- clients "
                               "that do not force SSL send credentials in cleartext")
                else:
                    tlsnote = "TLS capability unknown"
                plug = f"; default auth plugin {res['plugin']}" if res.get("plugin") else ""
                svc.scripts.append({"id": "mysql-handshake", "output":
                    f"{'MariaDB' if is_maria else 'MySQL'} {disp}{plug}; "
                    f"{tlsnote}. The server-initiated handshake was read WITHOUT "
                    f"sending anything -- version anchors CVE correlation; no "
                    f"authentication was attempted."})
        return

    if port in _MSSQL_PORTS or "ms-sql" in name or "mssql" in name:
        if svc.proto == "udp":
            insts = await mssql_browser_probe(host, port, cfg.timeout)
            if insts:
                if not svc.name:
                    svc.name = "ms-sql-m"
                if not svc.product:
                    svc.product = "Microsoft SQL Server"
                if "exposure" not in svc.sources:
                    svc.sources.append("exposure")
                listing = "; ".join(
                    f"{d.get('InstanceName', '?')}"
                    f"{' v' + d['Version'] if d.get('Version') else ''}"
                    f"{' tcp/' + d['tcp'] if d.get('tcp') else ''}"
                    for d in insts)
                for d in insts:                     # first explicit version wins
                    if d.get("Version") and not svc.version:
                        svc.version = d["Version"]
                        svc.cve_skip = False
                        break
                svc.scripts.append({"id": "mssql-browser", "output":
                    f"SQL Server Browser (UDP 1434) listed {len(insts)} "
                    f"instance(s) WITHOUT authentication: {listing}. The browser "
                    f"discloses instance names, versions and TCP ports to any "
                    f"client; disable it or firewall 1434/udp if not required."})
        else:
            res = await mssql_prelogin_probe(host, port, cfg.timeout)
            if res:
                if not svc.name:
                    svc.name = "ms-sql-s"
                if not svc.product:
                    svc.product = "Microsoft SQL Server"
                if res.get("version") and not svc.version:
                    svc.version = res["version"]
                    svc.cve_skip = False
                if "exposure" not in svc.sources:
                    svc.sources.append("exposure")
                enc = res.get("encryption", "")
                encnote = ""
                if enc == "not supported":
                    encnote = (" The instance offers NO TLS (ENCRYPT_NOT_SUP), "
                               "so login credentials transit in cleartext.")
                svc.scripts.append({"id": "mssql-prelogin", "output":
                    f"Microsoft SQL Server TDS PRELOGIN"
                    + (f" version {res['version']}" if res.get("version") else "")
                    + (f"; encryption {enc}" if enc else "") + "."
                    + encnote + " Read without authenticating (no login sent)."})
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
            # RTSPS cert/SAN pivot: grab the TLS cert so its subject/SAN names
            # (frequently internal-only hostnames) are stored on svc.tls and
            # harvested by the --web chain, mapped to this IP as vhost candidates.
            if rtsp_tls and not svc.tls:
                t = await tls_info(host, port, cfg.timeout)
                if t:
                    svc.tls.update(t)
                    names = list(dict.fromkeys(
                        n for n in ([t.get("subject_cn", "")]
                                    + list(t.get("sans", []) or [])) if n))
                    if names:
                        svc.scripts.append({"id": "rtsps-cert", "output":
                            f"RTSPS TLS certificate on {port} "
                            f"(issuer {t.get('issuer_cn') or 'n/a'}, "
                            f"{t.get('tls_version') or 'TLS'}): subject/SAN names "
                            f"{', '.join(names)}. Harvested as cert-only vhost "
                            f"candidates for the --web pivot (mapped to this IP), "
                            f"surfacing internal hostnames that exist only in the "
                            f"certificate."})
        return

    # Kerberos KDC (TCP 88). Unauthenticated AS-REQ (no pre-auth) per candidate
    # principal enumerates valid accounts and flags any whose pre-auth is
    # DISABLED (AS-REP returned = offline-crackable hash obtained with no
    # credentials = the only alert here). Needs a realm: --realm, else derived
    # from a dotted-FQDN scan target; a bare-IP target with no --realm is skipped.
    if port in _KRB_PORTS or "kerberos" in name:
        realm = (cfg.realm or "").strip()
        if not realm:
            for tok in (cfg.targets or (cfg.target or "").split()):
                tok = tok.strip()
                # a dotted hostname (has a letter, not a CIDR, not an IP/range);
                # the realm is its domain part. IP ranges ("10.0.0.1-50") have no
                # letters, so they are excluded without rejecting hyphenated names.
                if ("." in tok and "/" not in tok and not _looks_like_ip(tok)
                        and any(ch.isalpha() for ch in tok)):
                    realm = tok.split(".", 1)[1]
                    break
        if not realm:
            return                     # no realm -> cannot build an AS-REQ
        realm = realm.upper()
        res = await kerberos_probe(host, port, cfg.timeout, realm)
        if res:
            if not svc.name:
                svc.name = "kerberos-sec"
            if not svc.product:
                svc.product = "Kerberos KDC"
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            if res["wrong_realm"]:
                hint = res.get("realm_hint")
                svc.scripts.append({"id": "krb-wrong-realm", "output":
                    f"Kerberos KDC present but realm '{realm}' is not served"
                    + (f" (KDC indicated '{hint}')" if hint else "")
                    + ". Re-run with the correct --realm to enumerate accounts."})
            else:
                svc.scripts.append({"id": "krb-kdc", "output":
                    f"Kerberos KDC confirmed for realm {realm}. Unauthenticated "
                    f"AS-REQ probing (no pre-auth) tested "
                    f"{len(_KRB_DEFAULT_USERS)} default principal(s): "
                    f"{len(res['valid'])} valid, {len(res['unknown'])} absent."})
                if res["valid"]:
                    svc.scripts.append({"id": "krb-user-enum", "output":
                        "Valid principals enumerated WITHOUT credentials "
                        "(KDC_ERR_PREAUTH_REQUIRED / AS-REP vs "
                        "KDC_ERR_C_PRINCIPAL_UNKNOWN): "
                        + ", ".join(res["valid"]) + ". Kerberos pre-auth leaks "
                        "username validity to anyone who can reach 88 -- a "
                        "password-spray / roast target list."})
                for r in res["roastable"]:
                    svc.confidence = "high"
                    svc.extrainfo = "AS-REP-roastable account"
                    detail = (f" Hash: {r['hash']}" if r.get("hash")
                              else f" (enc-part etype {r.get('etype')}).")
                    svc.scripts.append({"id": "krb-asrep-roastable", "output":
                        f"Account '{r['user']}' has Kerberos pre-authentication "
                        f"DISABLED (DONT_REQUIRE_PREAUTH): the KDC returned an "
                        f"AS-REP to an unauthenticated AS-REQ, whose enc-part is "
                        f"encrypted with the account's key and is crackable "
                        f"offline = credential compromise with no prior access "
                        f"('AS-REP roasting').{detail} Require pre-authentication "
                        f"on this account."})
        return

    # WinRM / WS-Management (5985 plaintext / 5986 TLS, endpoint /wsman).
    # Unauthenticated posture: Identify (vendor/stack), offered auth schemes,
    # and -- via the NTLM primitive on /wsman -- the host identity. The only
    # alert is Basic offered over plaintext (cleartext credential capture);
    # everything else is informational. Returns so the generic web-NTLM
    # enrichment below does not double-probe /wsman.
    if port in _WINRM_PORTS or "wsman" in name or "winrm" in name:
        wtls = port == 5986 or bool(svc.tls) or is_tls_service(svc)
        res = await winrm_probe(host, port, cfg.timeout, wtls)
        if res:
            if not svc.name:
                svc.name = "wsman"
            if not svc.product:
                svc.product = "Microsoft WinRM"
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            ident, schemes, ntlm = res["identify"], res["schemes"], res["ntlm"]
            low = [s.lower() for s in schemes]
            if ident:
                parts = [f"{lbl} {ident[k]}" for k, lbl in
                         (("vendor", "vendor"), ("product_version", "product"),
                          ("protocol", "protocol")) if ident.get(k)]
                svc.scripts.append({"id": "winrm-identify", "output":
                    "WinRM/WS-Management answered an unauthenticated Identify: "
                    + "; ".join(parts) + ". Confirms the WS-Management stack "
                    "(MS-WSMV Identify is answerable without credentials; the OS "
                    "build is withheld in the unauthenticated response)."})
            if schemes:
                svc.scripts.append({"id": "winrm-auth-methods", "output":
                    f"WinRM accepts authentication scheme(s): "
                    f"{', '.join(schemes)}."})
            if ntlm:
                recon = [f"{lbl} {ntlm[k]}" for k, lbl in (
                    ("dns_domain", "AD domain"),
                    ("nb_domain", "NetBIOS/workgroup"),
                    ("dns_computer", "host"), ("nb_computer", "NetBIOS name"),
                    ("os", "OS build")) if ntlm.get(k)]
                if ntlm.get("os") and not svc.version:
                    svc.version = ntlm["os"]
                    svc.cve_skip = False
                if not svc.product or svc.product == "Microsoft WinRM":
                    svc.product = "Microsoft WinRM"
                if recon:
                    svc.scripts.append({"id": "winrm-ntlm-info", "output":
                        "WinRM /wsman Negotiate challenge disclosed host identity "
                        "WITHOUT authentication: " + "; ".join(recon) + " (NTLM "
                        "type-2 challenge; no credentials sent)."})
            plaintext = not (port == 5986 or bool(svc.tls) or is_tls_service(svc))
            if "basic" in low and plaintext:
                svc.confidence = "high"
                svc.extrainfo = "WinRM Basic over cleartext"
                svc.scripts.append({"id": "winrm-basic-cleartext", "output":
                    "WinRM offers HTTP Basic authentication over PLAINTEXT 5985 "
                    "(AllowUnencrypted). Credentials are sent base64-encoded with "
                    "no transport encryption, so any on-path observer captures "
                    "them, and a valid WinRM credential grants remote PowerShell "
                    "= full host takeover. Disable Basic and AllowUnencrypted; "
                    "require Negotiate/Kerberos with message encryption, or move "
                    "to HTTPS on 5986."})
            elif "basic" in low:
                svc.scripts.append({"id": "winrm-basic-tls", "output":
                    "WinRM offers HTTP Basic authentication, but over TLS (5986) "
                    "so credentials are encrypted in transit. Prefer "
                    "Negotiate/Kerberos and restrict Basic to limit credential "
                    "replay exposure."})
        return

    # HTTP(S)-based stores. Use TLS when the cert was already grabbed or the
    # port is TLS-only.
    tls = bool(svc.tls) or port in _TLS_EXPOSURE_PORTS

    # NTLM-over-HTTP identity leak (IIS/Exchange/RDWeb). Enrichment, not an alert:
    # a GET carrying only an NTLM NEGOTIATE makes the server disclose its OS build
    # + AD/NetBIOS names in the 401 challenge (no credentials sent). Non-returning
    # so the dedicated store/web checks below still run.
    if is_web_service(svc):
        htls = is_tls_service(svc) or bool(svc.tls)
        try:
            hit = await http_ntlm_probe(host, port, cfg.timeout, htls)
        except Exception:  # noqa: BLE001
            hit = None
        if hit:
            hpath, ntlm = hit
            if ntlm.get("os") and not svc.version:
                svc.version = ntlm["os"]
                svc.cve_skip = False
            if not svc.product and (ntlm.get("os") or ntlm.get("nb_domain")):
                svc.product = "Windows"
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            recon = [f"{lbl} {ntlm[k]}" for k, lbl in (
                        ("dns_domain", "AD domain"),
                        ("nb_domain", "NetBIOS/workgroup"),
                        ("dns_computer", "host"),
                        ("nb_computer", "NetBIOS name"),
                        ("os", "OS build")) if ntlm.get(k)]
            svc.scripts.append({"id": "http-ntlm-info", "output":
                f"HTTP NTLM endpoint {hpath} disclosed host identity WITHOUT "
                "authentication: " + "; ".join(recon) + ". The server answered an "
                "unauthenticated NTLM negotiate with a type-2 challenge naming its "
                "OS build and AD/NetBIOS identity (no credentials sent) -- typical "
                "of IIS/Exchange/RDWeb. Restrict or front these endpoints."})

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

    # Ops / control-plane HTTP services. Kept ahead of the gRPC branch because
    # several share its ports (MinIO/Portainer on 9000, Prometheus on 9090): a
    # confirmed product stops here, and only a genuine miss (None) falls through
    # to the gRPC detector below.
    if "prometheus" in name or port in _PROMETHEUS_PORTS:
        res = await prometheus_probe(host, port, cfg.timeout, tls)
        if res:
            _mark_exposure(svc, "prometheus", "Prometheus", res[0], res[1],
                "prometheus-unauth",
                f"Prometheus reachable WITHOUT authentication (Prometheus has no "
                f"auth of its own). An unauthenticated client can read every "
                f"scraped metric -- internal hostnames/IPs, the full target list, "
                f"build and config -- via /api/v1/*, and if the admin API is "
                f"enabled can delete series. Put it behind an authenticating "
                f"reverse proxy and firewall {port}.")
            return

    if "consul" in name or port in _CONSUL_PORTS:
        res = await consul_probe(host, port, cfg.timeout, tls)
        if res:
            _mark_exposure(svc, "consul", "HashiCorp Consul", res[0], res[1],
                "consul-unauth",
                f"Consul HTTP API reachable WITHOUT authentication (ACLs disabled "
                f"-- /v1/agent/self returned the full agent config and members). "
                f"An unauthenticated client can read the service catalog and KV "
                f"store (often secrets/config) and register or deregister "
                f"services. Enable ACLs with a default-deny policy, bind the API "
                f"to localhost, firewall {port}.")
            return

    if "vault" in name or port in _VAULT_PORTS:
        vres = await vault_probe(host, port, cfg.timeout, tls)
        if vres is not None:
            if not svc.name:
                svc.name = "vault"
            if not svc.product:
                svc.product = "HashiCorp Vault"
            if vres["version"] and not svc.version:
                svc.version = vres["version"]
                svc.cve_skip = False
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            state = "sealed" if vres["sealed"] else "UNSEALED"
            svc.scripts.append({"id": "vault-exposed", "output":
                f"HashiCorp Vault reachable on {port} ({state}). The seal-status "
                f"endpoint is unauthenticated by design, so this is informational "
                f"rather than an unauth-data finding; but a network-reachable "
                f"Vault widens the attack surface (auth brute-force, known-CVE "
                f"exploitation, and -- if ever started in dev mode -- a well-known "
                f"root token with in-memory storage). Restrict {port} to trusted "
                f"clients, terminate TLS, and enable audit logging."})
            return

    if ("rabbitmq" in name or "amqp" in name or port in _RABBITMQ_PORTS):
        res = await rabbitmq_probe(host, port, cfg.timeout, tls)
        if res:
            _mark_exposure(svc, "rabbitmq", "RabbitMQ Management", res[0], res[1],
                "rabbitmq-unauth",
                f"RabbitMQ management API answered /api/overview WITHOUT "
                f"authentication. An unauthenticated client can read vhosts, "
                f"users, queues and message rates and (via the same API) publish "
                f"or drain messages. Require authentication, remove the default "
                f"guest account, firewall {port}.")
            return

    if "minio" in name or port in _MINIO_PORTS:
        res = await minio_probe(host, port, cfg.timeout, tls)
        if res:
            _mark_exposure(svc, "minio", "MinIO", res[0], res[1],
                "minio-unauth",
                f"MinIO allows ANONYMOUS bucket access (an unauthenticated "
                f"ListBuckets returned the bucket list). Anonymous S3 access "
                f"exposes -- and, depending on policy, lets anyone write/delete -- "
                f"stored objects. Remove the anonymous/public bucket policies, "
                f"require signed requests, firewall {port}.")
            return

    if "portainer" in name or port in _PORTAINER_PORTS:
        res = await portainer_probe(host, port, cfg.timeout, tls)
        if res:
            _mark_exposure(svc, "portainer", "Portainer", res[0], res[1],
                "portainer-unauth",
                f"Portainer has NO admin account set yet "
                f"(/api/users/admin/check returned 404): anyone who reaches it "
                f"first can POST /api/users/admin/init to create the admin and "
                f"take over Portainer -- and thus every Docker/Kubernetes "
                f"environment it manages (equivalent to root on those hosts). "
                f"Complete the admin setup immediately and firewall {port} until "
                f"then.")
            return

    if "zookeeper" in name or port in _ZOOKEEPER_PORTS:
        res = await zookeeper_probe(host, port, cfg.timeout)
        if res:
            _mark_exposure(svc, "zookeeper", "Apache ZooKeeper", res[0], res[1],
                "zookeeper-unauth",
                f"ZooKeeper four-letter-word commands answer WITHOUT "
                f"authentication ('stat' returned server/version/client data). "
                f"The 4lw surface (stat/mntr/envi/conf/cons/dump/wchp) leaks "
                f"config, connected clients and znode paths, and ZooKeeper has no "
                f"auth on the data tree by default -- an unauthenticated client "
                f"can read and modify znodes (service registries, Kafka/HBase "
                f"metadata). Restrict the 4lw whitelist, enable SASL + ACLs, "
                f"firewall {port}.")
            return

    if "mqtt" in name or port in _MQTT_PORTS or port in _MQTTS_PORTS:
        mtls = (port in _MQTTS_PORTS or is_tls_service(svc)
                or "mqtts" in name or "ssl" in name)
        res = await mqtt_probe(host, port, cfg.timeout, mtls)
        if res:
            kind, banner = res
            if kind == "open":
                m = re.search(r"[0-9]+\.[0-9][0-9.]*", banner)
                ver = m.group(0) if m else ""
                _mark_exposure(svc, "mqtt", "MQTT broker", "open", ver,
                    "mqtt-unauth",
                    f"MQTT broker accepts anonymous connections WITHOUT "
                    f"authentication (an MQTT 3.1.1 CONNECT with no "
                    f"username/password was answered CONNACK 0x00). An "
                    f"unauthenticated client can subscribe to '#' and read every "
                    f"published message and publish to any topic -- on IoT/OT "
                    f"deployments that means reading sensor/telemetry data and "
                    f"issuing device commands. The probe only subscribed to the "
                    f"broker-version metadata topic, never an application topic. "
                    f"Set allow_anonymous false with a password file/ACLs and "
                    f"firewall {port}."
                    + (f' Broker version banner: "{banner}".' if banner else ""))
            elif kind == "auth":
                _mark_exposure(svc, "mqtt", "MQTT broker", "auth", "",
                               "mqtt-unauth", "")
            else:  # detected but anonymous refused for a non-credential reason
                if not svc.name:
                    svc.name = "mqtt"
                if not svc.product:
                    svc.product = "MQTT broker"
                if "exposure" not in svc.sources:
                    svc.sources.append("exposure")
                svc.scripts.append({"id": "mqtt-detected", "output":
                    f"MQTT broker detected on {port}; an anonymous CONNECT was "
                    f"refused for a non-credential reason (CONNACK != 0x00/0x04/"
                    f"0x05), so anonymous access could not be confirmed."})
            return

    if (port in _SMB_PORTS or "microsoft-ds" in name or "netbios-ssn" in name
            or name == "smb"):
        res = await smb_probe(host, port, cfg.timeout)
        if res:
            if not svc.name:
                svc.name = "microsoft-ds"
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            ntlm = res.get("ntlm") or {}
            if ntlm.get("os") and not svc.version:
                svc.version = ntlm["os"]
                svc.cve_skip = False
            if not svc.product:
                svc.product = ("Windows" if (ntlm.get("os") or ntlm.get("nb_domain"))
                               else "SMB")
            recon = [f"{lbl} {ntlm[k]}" for k, lbl in (
                        ("dns_domain", "AD domain"),
                        ("nb_domain", "NetBIOS/workgroup"),
                        ("dns_computer", "host"),
                        ("nb_computer", "NetBIOS name"),
                        ("os", "OS build")) if ntlm.get(k)]
            if recon:
                svc.scripts.append({"id": "smb-ntlm-info", "output":
                    "SMB/NTLM negotiation disclosed WITHOUT authentication: "
                    + "; ".join(recon) + ". A single anonymous SMB2 SESSION_SETUP "
                    "returns the host OS build and AD/NetBIOS names via the NTLM "
                    "challenge (no credentials sent). Restrict SMB to trusted "
                    "networks."})
            if res.get("smbv1"):
                svc.confidence = "high"
                svc.extrainfo = "SMBv1 enabled"
                svc.scripts.append({"id": "smbv1-enabled", "output":
                    "SMBv1 is ENABLED (the host answered an SMB1 'NT LM 0.12' "
                    "negotiate). SMBv1 is obsolete and carries the EternalBlue "
                    "(MS17-010 / CVE-2017-0144) wormable-RCE class and NTLM "
                    "downgrade exposure -- the vector behind WannaCry/NotPetya. "
                    "Disable SMBv1 entirely (it is off by default on current "
                    "Windows)."})
            if res.get("signing_required") is False:
                svc.confidence = "high"
                if not svc.extrainfo:
                    svc.extrainfo = "SMB signing not required"
                svc.scripts.append({"id": "smb-signing-not-required", "output":
                    "SMB signing is NOT required"
                    + (" (supported but optional)" if res.get("signing_enabled")
                       else " (disabled)")
                    + f" on dialect 0x{res['dialect']:04x}. An on-path attacker "
                    "can NTLM-relay authentication to this host (e.g. ntlmrelayx) "
                    "to execute commands or pivot without cracking a password. "
                    "Require SMB signing (GPO 'Microsoft network server: Digitally "
                    "sign communications (always)')."})
            elif res.get("signing_required") is True:
                svc.scripts.append({"id": "smb-signing-required", "output":
                    f"SMB signing is required on dialect 0x{res['dialect']:04x} "
                    "(good posture; NTLM relay to this host is blocked)."})
        return

    if (port in _NFS_PORTS or "rpcbind" in name or "sunrpc" in name
            or "portmap" in name or "nfs" in name):
        res = await nfs_probe(host, port, cfg.timeout)
        if res:
            if not svc.name:
                svc.name = "rpcbind"
            if not svc.product:
                svc.product = "rpcbind/NFS"
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            progs = sorted({_RPC_PROG_NAMES.get(pg, str(pg))
                            for (pg, v, pr, pt) in res["programs"]})
            svc.scripts.append({"id": "rpcbind-dump", "output":
                "rpcbind answered PMAPPROC_DUMP without authentication; "
                "registered RPC programs: " + ", ".join(progs) + ". This maps "
                "the host's RPC attack surface (NFS/NIS/quota/lock) to anyone "
                "who can reach 111."})
            exports = res["exports"]
            if exports:
                def _world(groups):
                    return (not groups) or any(
                        g in ("*", "", "(everyone)", "0.0.0.0", "0.0.0.0/0")
                        for g in groups)
                listing = "; ".join(
                    f"{d} -> {', '.join(g) if g else 'everyone'}"
                    for d, g in exports)
                svc.scripts.append({"id": "nfs-exports", "output":
                    f"mountd EXPORT listed {len(exports)} NFS export(s): "
                    f"{listing}."})
                world = [d for d, g in exports if _world(g)]
                if world:
                    svc.confidence = "high"
                    svc.extrainfo = "world-readable NFS export"
                    svc.scripts.append({"id": "nfs-export-world", "output":
                        "NFS export(s) shared with EVERYONE (no host "
                        f"restriction): {', '.join(world)}. Any client that can "
                        "reach NFS can mount and read these paths, and if "
                        "exported no_root_squash, write as root = host "
                        "compromise. Restrict exports to specific hosts/subnets "
                        "and keep root_squash enabled."})
        return

    if port in _LDAP_PORTS or port in _LDAPS_PORTS or "ldap" in name:
        ltls = (port in _LDAPS_PORTS or is_tls_service(svc)
                or "ldaps" in name or "ssl" in name)
        res = await ldap_probe(host, port, cfg.timeout, ltls)
        if res:
            rd = res["rootdse"]

            def _first(k):
                v = rd.get(k)
                if isinstance(v, list):
                    return v[0] if v else ""
                return v or ""

            if not svc.name:
                svc.name = "ldaps" if ltls else "ldap"
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            is_ad = bool(rd.get("domainControllerFunctionality")
                         or rd.get("forestFunctionality"))
            if not svc.product:
                svc.product = "Active Directory" if is_ad else "LDAP"
            if not res["anon_bind"]:
                svc.scripts.append({"id": "ldap-bind-refused", "output":
                    f"LDAP on {port} refused an anonymous simple bind "
                    "(authentication is enforced)."})
            else:
                nc = (rd.get("namingContexts")
                      or ([rd["defaultNamingContext"]]
                          if rd.get("defaultNamingContext") else []))
                bits = []
                if nc:
                    bits.append("naming contexts "
                                + ", ".join(nc if isinstance(nc, list) else [nc]))
                if _first("dnsHostName"):
                    bits.append("DC " + _first("dnsHostName"))
                for fl, lbl in (("domainControllerFunctionality", "DC"),
                                ("forestFunctionality", "forest"),
                                ("domainFunctionality", "domain")):
                    if _first(fl):
                        bits.append(f"{lbl} func-level {_first(fl)}")
                svc.scripts.append({"id": "ldap-rootdse", "output":
                    "Anonymous LDAP bind accepted; rootDSE readable WITHOUT "
                    "credentials: "
                    + ("; ".join(bits) if bits else "(rootDSE present)")
                    + ". This maps the directory (domain DN, DC, functional "
                    "levels) to any unauthenticated client."})
                if res["anon_read"]:
                    svc.confidence = "high"
                    svc.extrainfo = "anonymous LDAP directory read"
                    svc.scripts.append({"id": "ldap-anonymous-read", "output":
                        "Anonymous LDAP directory READ is enabled: an "
                        "unauthenticated subtree search of a naming context "
                        "returned directory objects. Anyone who can reach the "
                        "server can enumerate users, groups and computers (a "
                        "prime source for password-spray / Kerberoast "
                        "targeting). Disable anonymous reads (AD: dsHeuristics "
                        "bit; OpenLDAP: tighten the anonymous ACL)."})
        return

    if port in _RSYNC_PORTS or "rsync" in name:
        res = await rsync_probe(host, port, cfg.timeout)
        if res:
            if not svc.name:
                svc.name = "rsync"
            if not svc.product:
                svc.product = "rsync daemon"
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            mods = res["modules"]
            listing = ", ".join(n + (f" ({c})" if c else "") for n, c in mods)
            svc.scripts.append({"id": "rsync-modules", "output":
                f"rsync daemon listed {len(mods)} module(s) without "
                f"authentication: {listing}."})
            if res["first_auth"] is False:
                svc.confidence = "high"
                svc.extrainfo = "anonymous rsync module"
                svc.scripts.append({"id": "rsync-anon-module", "output":
                    f"rsync module '{res['first_module']}' accepts connections "
                    "WITHOUT authentication (@RSYNCD: OK, no AUTHREQD): anyone "
                    "who can reach 873 can read its contents (and, if the module "
                    "is not read-only, write to it). Set 'auth users' + a secrets "
                    "file and restrict 'hosts allow'."})
            elif res["first_auth"] is True:
                svc.scripts.append({"id": "rsync-module-auth", "output":
                    f"rsync module '{res['first_module']}' requires "
                    "authentication (@RSYNCD: AUTHREQD)."})
        return

    # gRPC / HTTP2 on a dedicated gRPC port (or a `grpc`-named service). Scoped
    # this way so HTTPS/2 web ports (also "h2") are never mislabelled as gRPC.
    if port in _GRPC_PORTS or "grpc" in name:
        tlsd = is_tls_service(svc)
        det = await grpc_probe(host, port, cfg.timeout, tlsd)
        if det is not None:
            if not svc.name:
                svc.name = "grpc"
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            refl = await grpc_list_services(host, port, cfg.timeout, tlsd)
            if refl and refl.get("services"):
                svc.confidence = "high"
                if not svc.product:
                    svc.product = "gRPC"
                svc.extrainfo = "gRPC server reflection ENABLED"
                svc.scripts.append({"id": "grpc-reflection-exposed", "output":
                    f"gRPC server reflection is ENABLED without authentication "
                    f"(via {refl['tool']}, transport {det['transport']}): the "
                    f"full service/method surface is enumerable. Services: "
                    f"{', '.join(refl['services'])}. Disable reflection on "
                    f"exposed deployments and require per-RPC authentication."})
                # drill into the method surface (native file_containing_symbol).
                try:
                    methods = await grpc_reflect_methods_native(
                        host, port, cfg.timeout, tlsd, refl["services"])
                except Exception:  # noqa: BLE001
                    methods = {}
                if methods:
                    def _fmt(ms):
                        shown = ", ".join(ms[:20])
                        return (shown + (" ..." if len(ms) > 20 else "")
                                if ms else "(no methods)")
                    listing = "; ".join(f"{s} [{_fmt(methods[s])}]"
                                        for s in sorted(methods))
                    svc.scripts.append({"id": "grpc-methods", "output":
                        f"gRPC method descriptors recovered via reflection "
                        f"(file_containing_symbol): {listing}. Each is a callable "
                        f"RPC on the unauthenticated surface -- the exact method "
                        f"names a client needs to invoke them without a .proto."})
            else:
                if refl is not None:
                    note = ("server reflection is disabled or requires "
                            "authentication")
                else:
                    note = "install grpcurl or grpcio to enumerate services"
                svc.scripts.append({"id": "grpc-detected", "output":
                    f"gRPC/HTTP2 server detected (transport {det['transport']}); "
                    f"{note}."})
            return
        # not gRPC (e.g. a plain HTTP app sharing a gRPC-ish port): fall through
        # so the ops/ONVIF HTTP checks still get a chance on this port.

    # Dahua DVRIP/DHIP management channel (TCP 37777). Read-only pre-auth realm
    # request; a hit identifies the device (and often its serial).
    if "dahua" in name or "dvrip" in name or port in _DAHUA_DVRIP_PORTS:
        dv = await dahua_dvrip_probe(host, port, cfg.timeout)
        if dv is not None:
            if not svc.name:
                svc.name = "dvrip"
            if not svc.product:
                svc.product = "Dahua"
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            realm = dv.get("realm")
            extra = f' Realm/serial "{realm}".' if realm else ""
            svc.scripts.append({"id": "dahua-dvrip", "output":
                f"Dahua DVRIP/DHIP device-management service detected on {port} "
                f"(private binary protocol; answered the pre-auth realm request)."
                f"{extra} This is the NetSDK control channel (login, config, PTZ, "
                f"stream) and a frequent target of Dahua authentication-bypass CVEs "
                f"(e.g. CVE-2021-33044 / CVE-2021-33045). It should never be "
                f"internet-facing; restrict {port} to a management network."})
            return

    # Hikvision SDK / HCNetSDK control channel (TCP 8000). The device greets on
    # connect, so we send nothing. 8000 is also an HTTP-alt / ONVIF port, so on a
    # miss we fall through to the web/ONVIF branch below.
    if "hikvision" in name or port in _HIK_SDK_PORTS:
        if await hikvision_sdk_probe(host, port, cfg.timeout):
            if not svc.name:
                svc.name = "hikvision-sdk"
            if not svc.product:
                svc.product = "Hikvision"
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            svc.scripts.append({"id": "hikvision-sdk", "output":
                f"Hikvision SDK / control service detected on {port} (private "
                f"binary protocol; the device sent its HCNetSDK handshake on "
                f"connect). This is the control channel (login, config, live "
                f"view) alongside the CVE-2017-7921 auth-bypass class on these "
                f"devices. It should never be internet-facing; restrict {port} to "
                f"a management network."})
            return

    # ttyd web terminal shares the camera default port 7681 (7682 for wss), but
    # an exposed ttyd is a browser shell (remote code execution), not a video
    # feed, so it is told apart BEFORE the camera WebSocket probe. Read-only HTTP
    # signature only -- the /ws shell socket is never opened. Also runs when a
    # prior phase already named the service "ttyd" (its Server header is ttyd/*).
    if port in _WS_CAM_PORTS or "ttyd" in name or "ttyd" in (svc.product or "").lower():
        tt_tls = (port == 7682 or is_tls_service(svc) or "wss" in name)
        tt = await ttyd_probe(host, port, cfg.timeout, tt_tls)
        if tt is not None:
            if not svc.name:
                svc.name = "ttyd"
            if not svc.product:
                svc.product = "ttyd"
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            if tt["auth"]:
                svc.scripts.append({"id": "ttyd-shell-auth", "output":
                    f"ttyd web terminal detected on {port}; the HTTP layer "
                    f"requires authentication (the read-only request was refused "
                    f"without credentials). The /ws shell socket was not opened."})
            else:
                svc.confidence = "high"
                svc.extrainfo = "UNAUTHENTICATED web shell"
                svc.scripts.append({"id": "ttyd-shell-unauth", "output":
                    f"ttyd web terminal is exposed WITHOUT authentication on "
                    f"{port}: the HTTP layer served the terminal page/token with "
                    f"no credentials, so anyone who can reach {port} gets an "
                    f"interactive shell in the browser (remote code execution). "
                    f"Detection stayed on the HTTP layer -- the /ws shell socket "
                    f"was never opened. Put ttyd behind authentication "
                    f"(ttyd -c user:pass, or a fronting proxy) and restrict "
                    f"{port} to trusted networks."})
            return

    # Camera WebSocket video preview (Hikvision ws 7681 / wss 7682, or any
    # camera-signalled port -- it can sit on 81 etc.). Unauthenticated upgrade +
    # read-only observation of what the device volunteers.
    if (port in _WS_CAM_PORTS or "hikvision" in name
            or (is_web_service(svc) and _looks_like_camera(svc))):
        ws_tls = (port == 7682 or is_tls_service(svc) or "wss" in name)
        ws = await ws_stream_probe(host, port, cfg.timeout, ws_tls)
        if ws is not None:
            scheme = "wss" if ws_tls else "ws"
            if not svc.name:
                svc.name = scheme
            if "exposure" not in svc.sources:
                svc.sources.append("exposure")
            if ws["binary"]:
                svc.confidence = "high"
                svc.extrainfo = "UNAUTHENTICATED camera WebSocket stream"
                svc.scripts.append({"id": "camera-ws-stream-unauth", "output":
                    f"Camera WebSocket video preview streams WITHOUT "
                    f"authentication on {port} ({scheme}): an unauthenticated "
                    f"RFC6455 upgrade was accepted and the device pushed "
                    f"{ws['video_bytes']} bytes of binary video frames with no "
                    f"session token. Anyone who can reach {port} can watch the "
                    f"live feed in a browser. Require the session/token auth on "
                    f"the WebSocket preview and restrict {port} to trusted "
                    f"networks."})
            elif ws["upgraded"]:
                svc.scripts.append({"id": "camera-ws-preview", "output":
                    f"Camera WebSocket video-preview endpoint reachable on {port} "
                    f"({scheme}) and accepted an UNAUTHENTICATED upgrade"
                    + (" (valid Sec-WebSocket-Accept)" if ws["accept_ok"] else "")
                    + ". No video frames were volunteered without an explicit "
                      "start, so anonymous playback is not confirmed -- a device "
                      "that requires an in-band session token or a start message "
                      "will not stream here. Verify the preview enforces its "
                      f"token and restrict {port} to trusted networks."
                    + (f" First text frame: {ws['text']}" if ws["text"] else "")})
            elif ws.get("auth"):
                svc.scripts.append({"id": "camera-ws-auth", "output":
                    f"Camera WebSocket preview endpoint detected on {port} "
                    f"({scheme}); the unauthenticated upgrade was refused "
                    f"({ws['status']}) -- authentication is enforced."})
            # dedicated WS ports (7681/7682) or a confirmed stream: done. On a
            # dual-purpose web port with no stream, fall through to ONVIF/web.
            if port in _WS_CAM_PORTS or ws["binary"]:
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

    def _udp_svc(port: int, name: str) -> Service:
        s = next((s for s in services
                  if s.port == port and s.proto == "udp"), None)
        if s is None:
            s = Service(port=port, proto="udp", state="open", name=name)
            services.append(s)
        if "exposure" not in s.sources:
            s.sources.append("exposure")
        return s

    # Host-level SNMP (UDP 161). Runs once per host regardless of UDP scanning,
    # since 161 is rarely in a default TCP scan. A GetRequest answered with a
    # well-known community string is a full read of the device over SNMP.
    try:
        snmp = await snmp_probe(host, 161, cfg.timeout)
    except Exception:  # noqa: BLE001
        snmp = None
    if snmp:
        svc = _udp_svc(161, "snmp")
        if not svc.product:
            svc.product = "SNMP agent"
        svc.confidence = "high"
        svc.extrainfo = f"UNAUTHENTICATED (community \"{snmp['community']}\")"
        one_line = " ".join(snmp["sysdescr"].split())[:300]
        svc.scripts.append({"id": "snmp-unauth", "output":
            f"SNMP agent readable with the well-known community "
            f"\"{snmp['community']}\" (SNMP v{snmp['version']}): a GetRequest for "
            f"sysDescr.0 returned \"{one_line}\". The whole MIB -- interfaces, ARP "
            f"and routing tables, running processes, and on many devices "
            f"credentials -- is readable, and a writable community additionally "
            f"allows configuration changes. Change the community strings, restrict "
            f"SNMP to a management network, or move to SNMPv3 with auth+priv."})

    # Host-level IPMI cipher-zero (UDP 623). A BMC that accepts cipher suite 0
    # grants an administrative session with no password -- full out-of-band
    # control of the server (power, serial-over-LAN, virtual media).
    try:
        ipmi = await ipmi_cipher_zero_probe(host, 623, cfg.timeout)
    except Exception:  # noqa: BLE001
        ipmi = None
    if ipmi:
        svc = _udp_svc(623, "asf-rmcp")
        if not svc.product:
            svc.product = "IPMI/BMC"
        if ipmi[0] == "open":
            svc.confidence = "high"
            svc.extrainfo = "IPMI cipher-zero auth bypass"
            svc.scripts.append({"id": "ipmi-cipher-zero", "output":
                "IPMI 2.0 BMC accepts cipher suite 0 (an RMCP+ Open Session "
                "Request with all algorithms set to 0 returned status 0): an "
                "attacker can open an ADMINISTRATOR session with no password and "
                "gain full out-of-band control -- power cycling, serial-over-LAN, "
                "virtual media (boot an attacker ISO), and BMC user management. "
                "Disable cipher suite 0 (list only 3/17), firewall UDP 623."})
        else:
            svc.scripts.append({"id": "ipmi-detected", "output":
                "IPMI 2.0 BMC detected on UDP 623 (answered an RMCP+ Open Session "
                "Request); cipher suite 0 was refused. Note BMCs are also exposed "
                "to the IPMI 2.0 RAKP password-hash disclosure -- restrict UDP 623 "
                "to a management network and use strong BMC passwords."})

    # Host-level SSDP/UPnP (UDP 1900, unicast M-SEARCH). UPnP discovery is
    # unauthenticated by design, so this is INFORMATIONAL enumeration (device
    # model/firmware for CVE anchoring + advertised service surface), never an
    # unauth-access alert. An advertised Internet Gateway control service
    # (WANIPConnection/WANPPPConnection) is called out as a hardening concern.
    try:
        ssdp = await ssdp_probe(host, 1900, min(cfg.timeout, 3.0))
    except Exception:  # noqa: BLE001
        ssdp = None
    if ssdp:
        svc = _udp_svc(1900, "upnp")
        desc = {}
        if ssdp["locations"]:
            try:
                desc = await ssdp_describe(host, ssdp["locations"][0],
                                           min(cfg.timeout, 3.0))
            except Exception:  # noqa: BLE001
                desc = {}
        label = " ".join(v for v in (desc.get("manufacturer"),
                                      desc.get("model")) if v).strip()
        if label and not svc.product:
            svc.product = label
        elif ssdp["server"] and not svc.product:
            svc.product = ssdp["server"]
        if desc.get("model_number") and not svc.version:
            nv = _norm_ver(desc["model_number"])
            if nv:
                svc.version = nv
                svc.cve_skip = False
        igd = sorted({s for s in desc.get("services", [])
                      if "WANIPConnection" in s or "WANPPPConnection" in s})
        bits = []
        if ssdp["server"]:
            bits.append(f"SERVER: {ssdp['server']}")
        if desc.get("friendly"):
            bits.append(f"device: {desc['friendly']}")
        if label:
            bits.append("model: " + label
                        + (f" {desc['model_number']}"
                           if desc.get("model_number") else ""))
        if ssdp["locations"]:
            bits.append(f"LOCATION: {ssdp['locations'][0]}")
        if desc.get("services"):
            bits.append(f"{len(desc['services'])} UPnP services"
                        + (f" incl. {', '.join(igd)}" if igd else ""))
        elif ssdp["sts"]:
            bits.append("ST: " + ", ".join(ssdp["sts"][:6]))
        note = ("; ".join(bits)
                + ". UPnP discovery is unauthenticated by design; this "
                  "enumerates the device (model/firmware and advertised "
                  "services) for attack-surface mapping.")
        if igd:
            note += (" The device advertises an Internet Gateway control "
                     "service (WANIPConnection/WANPPPConnection): if this UPnP "
                     "IGD is reachable from an untrusted network, clients can "
                     "map arbitrary ports through the gateway -- restrict UPnP "
                     "to the LAN.")
        svc.scripts.append({"id": "ssdp-upnp", "output":
            "SSDP/UPnP answered a unicast M-SEARCH (UDP 1900): " + note})

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
