"""Vendor camera CGI: unauth info disclosure + HTTP Basic/Digest default-cred.
Loopback HTTP server emulates Hikvision ISAPI / Dahua magicBox and validates the
client's Digest response byte-for-byte against an independent MD5 reference."""
import asyncio
import hashlib

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service

REALM, NONCE = "CamWeb", "n0nce123"

_HIK_XML = ('<?xml version="1.0" encoding="UTF-8"?><DeviceInfo>'
            '<deviceName>Cam</deviceName><model>DS-2CD2042</model>'
            '<firmwareVersion>V5.5.800</firmwareVersion></DeviceInfo>')
_DAHUA_TXT = ("deviceType=IPC-HDW4631\r\nserialNumber=ABC123\r\n"
              "softwareVersion=2.800\r\n")


def _good_digest(user, pw, realm, nonce, method, uri):
    h = lambda s: hashlib.md5(s.encode()).hexdigest()  # noqa: E731
    return h(f"{h(f'{user}:{realm}:{pw}')}:{nonce}:{h(f'{method}:{uri}')}")


def _resp(status, body="", ctype="text/plain", wwwauth=""):
    b = body.encode()
    lines = [f"HTTP/1.0 {status}", f"Content-Type: {ctype}",
             f"Content-Length: {len(b)}", "Connection: close"]
    if wwwauth:
        lines.append(f"WWW-Authenticate: {wwwauth}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + b


def _make_server(mode):
    async def handler(reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
        except Exception:
            data = b""
        text = data.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0].split(" ")
        method = first[0] if first else ""
        path = first[1] if len(first) > 1 else ""
        hdrs = {}
        for ln in text.split("\r\n")[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        auth = hdrs.get("authorization", "")

        def ok(user, pw):
            return (auth.startswith("Digest")
                    and f'response="{_good_digest(user, pw, REALM, NONCE, "GET", path)}"'
                    in auth)

        chal = f'Digest realm="{REALM}", nonce="{NONCE}"'
        out = _resp("404 Not Found")                      # ONVIF POST + snapshots
        if method == "GET" and path == "/ISAPI/System/deviceInfo":
            if mode == "hik-unauth":
                out = _resp("200 OK", _HIK_XML, "application/xml")
            elif mode == "hik-digest":
                out = (_resp("200 OK", _HIK_XML, "application/xml")
                       if ok("admin", "12345")
                       else _resp("401 Unauthorized", wwwauth=chal))
        elif method == "GET" and path.startswith("/cgi-bin/magicBox.cgi"):
            if mode == "dahua-digest":
                out = (_resp("200 OK", _DAHUA_TXT) if ok("admin", "admin")
                       else _resp("401 Unauthorized", wwwauth=chal))
        try:
            writer.write(out)
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _run(mode, product="Hikvision", cam_creds=True):
    async def run():
        server = await asyncio.start_server(_make_server(mode), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        svc = Service(port=port, name="http", product=product, state="open")
        cfg = ScanConfig(target="x", timeout=2.0, concurrency=5, cam_creds=cam_creds)
        try:
            await fp.check_exposure(cfg, "127.0.0.1", svc)
        finally:
            server.close()
            await server.wait_closed()
        return svc
    return asyncio.run(run())


def _ids(svc):
    return {s["id"] for s in svc.scripts}


def test_hikvision_unauth_isapi_disclosure():
    svc = _run("hik-unauth")
    assert "cam-cgi-unauth" in _ids(svc)
    assert "cam-cgi-unauth" in fp.EXPOSURE_ALERT_IDS
    assert "DS-2CD2042" in (svc.product or "")


def test_hikvision_default_creds_isapi():
    svc = _run("hik-digest")
    assert "cam-cgi-default-creds" in _ids(svc)
    assert "admin:12345" in svc.extrainfo
    assert svc.version == "5.5.800"           # V5.5.800 -> normalized


def test_dahua_default_creds_magicbox():
    svc = _run("dahua-digest", product="Dahua IPC")
    assert "cam-cgi-default-creds" in _ids(svc)
    assert "admin:admin" in svc.extrainfo
    assert svc.version == "2.800"


def test_cam_creds_off_skips_vendor_cred_spray():
    svc = _run("hik-digest", cam_creds=False)
    assert "cam-cgi-default-creds" not in _ids(svc)   # active step disabled
    assert "cam-cgi-unauth" not in _ids(svc)          # it 401s, no disclosure


def test_no_cgi_probe_on_non_camera():
    # even though the server would answer ISAPI, a non-camera service isn't probed
    svc = _run("hik-unauth", product="nginx")
    assert not any(i.startswith("cam-cgi") for i in _ids(svc))
