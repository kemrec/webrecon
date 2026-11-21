"""ONVIF recon (SOAP presence + unauth device-info + WS-UsernameToken default
creds). A loopback HTTP server speaks canned SOAP per mode and, in auth mode,
VERIFIES the WS-Security PasswordDigest the client sends against a real SHA1
reference -- so a pass proves the client's token is wire-correct."""
import asyncio
import base64
import hashlib
import re

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service

_DATETIME = (
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
    '<tds:GetSystemDateAndTimeResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
    '<tds:SystemDateAndTime><tt:UTCDateTime xmlns:tt="http://www.onvif.org/ver10/schema">'
    '<tt:Time><tt:Hour>12</tt:Hour><tt:Minute>30</tt:Minute><tt:Second>5</tt:Second></tt:Time>'
    '<tt:Date><tt:Year>2026</tt:Year><tt:Month>11</tt:Month><tt:Day>21</tt:Day></tt:Date>'
    '</tt:UTCDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>'
    '</s:Body></s:Envelope>')

_DEVINFO = (
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
    '<tds:GetDeviceInformationResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
    '<tds:Manufacturer>ACME</tds:Manufacturer><tds:Model>IPCam-9000</tds:Model>'
    '<tds:FirmwareVersion>5.4.1</tds:FirmwareVersion><tds:SerialNumber>SN123</tds:SerialNumber>'
    '</tds:GetDeviceInformationResponse></s:Body></s:Envelope>')

_FAULT = (
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
    '<s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode>'
    '<s:Value>ter:NotAuthorized</s:Value></s:Subcode></s:Code></s:Fault>'
    '</s:Body></s:Envelope>')

_USERS = (
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
    '<tds:GetUsersResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
    '<tds:User><tds:Username>admin</tds:Username>'
    '<tds:UserLevel>Administrator</tds:UserLevel></tds:User>'
    '<tds:User><tds:Username>viewer</tds:Username>'
    '<tds:UserLevel>User</tds:UserLevel></tds:User>'
    '</tds:GetUsersResponse></s:Body></s:Envelope>')

_PROFILES = (
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
    '<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl" '
    'xmlns:tt="http://www.onvif.org/ver10/schema">'
    '<trt:Profiles token="Profile_1" fixed="true"><tt:Name>mainStream</tt:Name>'
    '<tt:VideoEncoderConfiguration><tt:Encoding>H264</tt:Encoding>'
    '<tt:Resolution><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height>'
    '</tt:Resolution></tt:VideoEncoderConfiguration></trt:Profiles>'
    '<trt:Profiles token="Profile_2"><tt:Name>subStream</tt:Name>'
    '<tt:VideoEncoderConfiguration><tt:Encoding>H265</tt:Encoding>'
    '<tt:Resolution><tt:Width>640</tt:Width><tt:Height>480</tt:Height>'
    '</tt:Resolution></tt:VideoEncoderConfiguration></trt:Profiles>'
    '</trt:GetProfilesResponse></s:Body></s:Envelope>')

_STREAM_URI = (
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
    '<trt:GetStreamUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">'
    '<trt:MediaUri xmlns:tt="http://www.onvif.org/ver10/schema">'
    '<tt:Uri>rtsp://cam/Streaming/Channels/101?token=abc</tt:Uri>'
    '</trt:MediaUri></trt:GetStreamUriResponse></s:Body></s:Envelope>')

_SNAP_URI = (
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
    '<trt:GetSnapshotUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">'
    '<trt:MediaUri xmlns:tt="http://www.onvif.org/ver10/schema">'
    '<tt:Uri>http://cam/onvif-http/snapshot</tt:Uri>'
    '</trt:MediaUri></trt:GetSnapshotUriResponse></s:Body></s:Envelope>')


def _http(status, body):
    b = body.encode()
    return (f"HTTP/1.0 {status}\r\nContent-Type: application/soap+xml\r\n"
            f"Content-Length: {len(b)}\r\nConnection: close\r\n\r\n").encode() + b


def _token_valid(xml, user, pw):
    """Recompute the WS-UsernameToken PasswordDigest the real ONVIF way."""
    gu = re.search(r"<[^>]*Username[^>]*>([^<]+)<", xml)
    gp = re.search(r'<[^>]*Password[^>]*>([^<]+)<', xml)
    gn = re.search(r"<[^>]*Nonce[^>]*>([^<]+)<", xml)
    gc = re.search(r"<[^>]*Created[^>]*>([^<]+)<", xml)
    if not (gu and gp and gn and gc) or gu.group(1) != user:
        return False
    nonce = base64.b64decode(gn.group(1))
    expect = base64.b64encode(
        hashlib.sha1(nonce + gc.group(1).encode() + pw.encode()).digest()).decode()
    return gp.group(1) == expect


def _make_server(mode):
    async def handler(reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(8192), timeout=2.0)
        except Exception:
            data = b""
        text = data.decode("latin-1", "replace")
        gated = _token_valid(text, "admin", "admin")
        if mode == "notonvif":
            out = _http("404 Not Found", "<html>no</html>")
        elif "GetSystemDateAndTime" in text:
            out = _http("200 OK", _DATETIME)
        elif "GetDeviceInformation" in text:
            if mode in ("unauth", "enum-unauth"):
                out = _http("200 OK", _DEVINFO)
            elif mode in ("auth-basic-default", "digest", "enum-digest") and gated:
                out = _http("200 OK", _DEVINFO)
            else:
                out = _http("400 Bad Request", _FAULT)
        elif "GetUsers" in text:
            if mode == "enum-unauth" or (mode == "enum-digest" and gated):
                out = _http("200 OK", _USERS)
            else:
                out = _http("400 Bad Request", _FAULT)
        elif "GetProfiles" in text:
            if mode == "enum-unauth" or (mode == "enum-digest" and gated):
                out = _http("200 OK", _PROFILES)
            else:
                out = _http("400 Bad Request", _FAULT)
        elif "GetStreamUri" in text:
            if mode == "enum-unauth" or (mode == "enum-digest" and gated):
                out = _http("200 OK", _STREAM_URI)
            else:
                out = _http("400 Bad Request", _FAULT)
        elif "GetSnapshotUri" in text:
            if mode == "enum-unauth" or (mode == "enum-digest" and gated):
                out = _http("200 OK", _SNAP_URI)
            else:
                out = _http("400 Bad Request", _FAULT)
        else:
            # GetServices (and anything else) fault -> media enum falls back to
            # the device_service endpoint, which the handler answers above.
            out = _http("400 Bad Request", _FAULT)
        try:
            writer.write(out)
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _run(mode, cam_creds=True):
    async def run():
        # mode 'notonvif' must reject even GetSystemDateAndTime
        srv_mode = mode
        server = await asyncio.start_server(_make_server(srv_mode), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        svc = Service(port=port, name="http", state="open")
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


def test_onvif_utc_created_parses_onvif_field_order():
    # Time(Hour/Min/Sec) comes BEFORE Date(Year/Month/Day) in ONVIF
    assert fp._onvif_utc_created(_DATETIME) == "2026-11-21T12:30:05Z"


def test_onvif_ws_security_digest_is_wire_correct():
    created = "2026-11-21T12:30:05Z"
    hdr = fp._onvif_ws_security("admin", "admin", created)
    assert _token_valid(hdr, "admin", "admin")      # server-side reference accepts it


def test_onvif_unauthenticated_device_info_is_critical():
    svc = _run("unauth")
    assert "onvif-unauth" in _ids(svc)
    assert "onvif-unauth" in fp.EXPOSURE_ALERT_IDS
    assert "ACME" in (svc.product or "")


def test_onvif_default_creds_via_ws_username_token():
    svc = _run("digest")
    assert "onvif-auth" in _ids(svc)
    assert "onvif-default-creds" in _ids(svc)
    assert "admin:admin" in svc.extrainfo
    assert svc.version == "5.4.1"                    # firmware promoted


def test_onvif_creds_flag_off_skips_active_step():
    svc = _run("digest", cam_creds=False)
    assert "onvif-auth" in _ids(svc)
    assert "onvif-default-creds" not in _ids(svc)


def test_non_onvif_web_service_emits_nothing():
    svc = _run("notonvif")
    assert not any(i.startswith("onvif") for i in _ids(svc))


def test_parse_onvif_users_direct():
    users = fp._parse_onvif_users(_USERS.encode())
    assert {u["name"] for u in users} == {"admin", "viewer"}
    by = {u["name"]: u["level"] for u in users}
    assert by["admin"] == "Administrator" and by["viewer"] == "User"


def test_parse_onvif_profiles_direct():
    profs = fp._parse_onvif_profiles(_PROFILES.encode())
    assert [p["token"] for p in profs] == ["Profile_1", "Profile_2"]
    assert profs[0]["name"] == "mainStream"
    assert profs[0]["resolution"] == "1920x1080"
    assert profs[0]["encoding"] == "H264"
    assert profs[1]["resolution"] == "640x480"


def test_parse_xaddr_keeps_path_and_port():
    # adopt the XAddr path/port/scheme (we still connect to the scanned host)
    assert fp._parse_xaddr("http://192.168.1.5:8899/onvif/Media", 80, False) == (
        "/onvif/Media", 8899, False)
    path, port, tls = fp._parse_xaddr("https://cam/onvif/media_service", 80, False)
    assert (path, port, tls) == ("/onvif/media_service", 443, True)
    # garbage falls back to the device_service endpoint
    assert fp._parse_xaddr("not a url", 8000, True) == (fp._ONVIF_PATH, 8000, True)


def test_onvif_unauth_enumerates_users_and_profiles():
    svc = _run("enum-unauth")
    assert "onvif-unauth" in _ids(svc)
    assert "onvif-users" in _ids(svc)
    assert "onvif-media-profiles" in _ids(svc)
    out = {s["id"]: s["output"] for s in svc.scripts}
    assert "admin [Administrator]" in out["onvif-users"]
    assert "viewer [User]" in out["onvif-users"]
    assert "mainStream" in out["onvif-media-profiles"]
    assert "1920x1080" in out["onvif-media-profiles"]
    assert "H264" in out["onvif-media-profiles"]
    # GetStreamUri / GetSnapshotUri recovered the real media endpoints
    assert "stream=rtsp://cam/Streaming/Channels/101" in out["onvif-media-profiles"]
    assert "snapshot=http://cam/onvif-http/snapshot" in out["onvif-media-profiles"]


def test_onvif_first_uri_parses_mediauri():
    assert fp._onvif_first_uri(_STREAM_URI.encode()) == (
        "rtsp://cam/Streaming/Channels/101?token=abc")
    assert fp._onvif_first_uri(_SNAP_URI.encode()) == (
        "http://cam/onvif-http/snapshot")


def test_onvif_default_creds_then_enumerates():
    # the follow-up GetUsers/GetProfiles must carry a wire-correct WS-Security
    # token (fresh nonce per request), proving the mksec factory path works.
    svc = _run("enum-digest")
    assert "onvif-default-creds" in _ids(svc)
    assert "onvif-users" in _ids(svc)
    assert "onvif-media-profiles" in _ids(svc)
    out = {s["id"]: s["output"] for s in svc.scripts}
    assert "admin" in out["onvif-users"]
    assert "subStream" in out["onvif-media-profiles"]
