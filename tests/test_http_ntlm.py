"""NTLM-over-HTTP identity leak (IIS/Exchange/RDWeb). An endpoint offering
WWW-Authenticate: NTLM answers an unauthenticated NTLM NEGOTIATE with a type-2
CHALLENGE that names the host OS build + AD/NetBIOS identity. No credentials are
sent. Informational recon. Loopback only."""
import asyncio
import base64

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


def _mk_type2() -> bytes:
    def av(aid, s):
        b = s.encode("utf-16-le")
        return aid.to_bytes(2, "little") + len(b).to_bytes(2, "little") + b
    ti = av(2, "CONTOSO") + av(1, "MAIL01") + av(4, "contoso.com") + b"\x00\x00\x00\x00"
    flags = 0x02000000 | 0x00800000
    msg = (b"NTLMSSP\x00" + (2).to_bytes(4, "little") + b"\x00" * 8
           + flags.to_bytes(4, "little") + b"\x22" * 8 + b"\x00" * 8)
    ti_off = len(msg) + 8 + 8
    msg += (len(ti).to_bytes(2, "little") + len(ti).to_bytes(2, "little")
            + ti_off.to_bytes(4, "little"))
    msg += bytes([10, 0]) + (17763).to_bytes(2, "little") + b"\x00\x00\x00\x0f"
    msg += ti
    return msg


def _http_ntlm_server(mode: str):
    type2_b64 = base64.b64encode(_mk_type2()).decode()

    async def handler(reader, writer):
        try:
            req = await asyncio.wait_for(reader.read(4096), timeout=2.0)
        except Exception:
            req = b""
        text = req.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        path = first.split(" ")[1] if " " in first else "/"
        has_auth = "\nauthorization:" in ("\n" + text.lower())

        def send(status, hdrs=b"", body=b""):
            writer.write(f"HTTP/1.0 {status}\r\n".encode() + hdrs
                         + b"Content-Length: " + str(len(body)).encode()
                         + b"\r\nConnection: close\r\n\r\n" + body)

        if mode == "plain":
            send("200 OK", b"Server: nginx\r\n", b"hi")
        elif mode == "root_ntlm":
            if path == "/":
                if has_auth:
                    send("401 Unauthorized",
                         f"WWW-Authenticate: NTLM {type2_b64}\r\n".encode())
                else:
                    send("401 Unauthorized", b"WWW-Authenticate: NTLM\r\n")
            else:
                send("404 Not Found")
        elif mode == "iis_ews":
            if path == "/":
                send("200 OK", b"Server: Microsoft-IIS/10.0\r\n", b"ok")
            elif path == "/ews/":
                if has_auth:
                    send("401 Unauthorized",
                         f"WWW-Authenticate: NTLM {type2_b64}\r\n".encode())
                else:                       # two schemes; NTLM listed last
                    send("401 Unauthorized",
                         b"WWW-Authenticate: Negotiate\r\n"
                         b"WWW-Authenticate: NTLM\r\n")
            else:
                send("404 Not Found")
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _probe(mode, timeout=1.0):
    async def run():
        srv = await asyncio.start_server(_http_ntlm_server(mode), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.http_ntlm_probe("127.0.0.1", port, timeout, False)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


def test_probe_root_ntlm():
    hit = _probe("root_ntlm")
    assert hit is not None
    path, info = hit
    assert path == "/"
    assert info["os"] == "10.0.17763"
    assert info["dns_domain"] == "contoso.com"
    assert info["nb_computer"] == "MAIL01"


def test_probe_iis_sweeps_to_ews():
    hit = _probe("iis_ews")
    assert hit is not None
    path, info = hit
    assert path == "/ews/"
    assert info["nb_domain"] == "CONTOSO"


def test_probe_plain_web_is_none():
    # non-Microsoft, no NTLM offered -> one GET, no sweep, None
    assert _probe("plain") is None


# --- check_exposure dispatch ------------------------------------------------
def test_dispatch_http_ntlm_is_informational_enrichment():
    svc = Service(port=0, name="http", state="open")

    async def run():
        srv = await asyncio.start_server(_http_ntlm_server("root_ntlm"),
                                         "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())

    ids = {s["id"] for s in svc.scripts}
    assert "http-ntlm-info" in ids
    assert "http-ntlm-info" not in fp.EXPOSURE_ALERT_IDS   # recon, not an alert
    assert svc.product == "Windows" and svc.version == "10.0.17763"
