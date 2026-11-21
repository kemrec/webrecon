"""WinRM / WS-Management posture (TCP 5985 plaintext / 5986 TLS, /wsman).

Read-only, dependency-free, no credentials sent. Three unauthenticated signals:
an MS-WSMV Identify (vendor/stack), the offered WWW-Authenticate schemes, and
the NTLM type-2 challenge (OS/AD identity leak). The ONLY alert is Basic offered
over plaintext (cleartext credential capture); everything else is informational.
Loopback only -- no real WinRM host is contacted."""
import asyncio
import base64

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service

_IDENTIFY_BODY = (
    b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    b'xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/'
    b'wsmanidentity.xsd"><s:Body><wsmid:IdentifyResponse>'
    b'<wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd'
    b'</wsmid:ProtocolVersion>'
    b'<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>'
    b'<wsmid:ProductVersion>OS: 0.0.0 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>'
    b'</wsmid:IdentifyResponse></s:Body></s:Envelope>')


def _mk_type2() -> bytes:
    def av(aid, s):
        b = s.encode("utf-16-le")
        return aid.to_bytes(2, "little") + len(b).to_bytes(2, "little") + b
    ti = av(2, "CONTOSO") + av(1, "DC01") + av(4, "contoso.com") + b"\x00\x00\x00\x00"
    flags = 0x02000000 | 0x00800000
    msg = (b"NTLMSSP\x00" + (2).to_bytes(4, "little") + b"\x00" * 8
           + flags.to_bytes(4, "little") + b"\x22" * 8 + b"\x00" * 8)
    ti_off = len(msg) + 8 + 8
    msg += (len(ti).to_bytes(2, "little") + len(ti).to_bytes(2, "little")
            + ti_off.to_bytes(4, "little"))
    msg += bytes([10, 0]) + (17763).to_bytes(2, "little") + b"\x00\x00\x00\x0f"
    msg += ti
    return msg


def _winrm_server(schemes, *, identify=True, ntlm=True,
                  server_hdr="Microsoft-HTTPAPI/2.0", plain=False):
    """A loopback WinRM listener. `schemes` is the list of WWW-Authenticate
    schemes offered on an unauthenticated 401; each is emitted on its OWN
    header line (as http.sys does)."""
    type2_b64 = base64.b64encode(_mk_type2()).decode()

    async def handler(reader, writer):
        try:
            req = await asyncio.wait_for(reader.read(8192), timeout=2.0)
        except Exception:
            req = b""
        low = req.decode("latin-1", "replace").lower()
        has_auth = "\nauthorization:" in ("\n" + low)
        is_identify = "identifyresponse" not in low and "identify" in low

        def send(status, hdrs=b"", body=b""):
            writer.write(f"HTTP/1.0 {status}\r\n".encode() + hdrs
                         + b"Content-Length: " + str(len(body)).encode()
                         + b"\r\nConnection: close\r\n\r\n" + body)

        if plain:
            send("200 OK", b"Server: nginx\r\n", b"hi")
        elif has_auth and ntlm:
            send("401 Unauthorized",
                 f"WWW-Authenticate: Negotiate {type2_b64}\r\n".encode())
        elif is_identify and identify:
            send("200 OK", f"Server: {server_hdr}\r\n".encode(), _IDENTIFY_BODY)
        else:
            hdrs = ("".join(f"WWW-Authenticate: {s}\r\n" for s in schemes)
                    + f"Server: {server_hdr}\r\n").encode()
            send("401 Unauthorized", hdrs)
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _probe(server, timeout=1.0):
    async def run():
        srv = await asyncio.start_server(server, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await fp.winrm_probe("127.0.0.1", port, timeout, False)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


# --- probe -----------------------------------------------------------------
def test_identify_and_schemes_and_ntlm():
    res = _probe(_winrm_server(["Negotiate", "Kerberos", "Basic"]))
    assert res is not None
    assert res["identify"]["vendor"] == "Microsoft Corporation"
    assert "Stack: 3.0" in res["identify"]["product_version"]
    assert res["schemes"] == ["Negotiate", "Kerberos", "Basic"]
    assert res["ntlm"]["os"] == "10.0.17763"
    assert res["ntlm"]["dns_domain"] == "contoso.com"
    assert res["ntlm"]["nb_computer"] == "DC01"


def test_schemes_on_first_401_when_identify_refused():
    # Hardened listener that 401s even the Identify: schemes read on request 1.
    res = _probe(_winrm_server(["Negotiate"], identify=False))
    assert res is not None
    assert res["identify"] == {}
    assert res["schemes"] == ["Negotiate"]
    assert res["ntlm"]["nb_domain"] == "CONTOSO"


def test_combined_comma_separated_schemes():
    res = _probe(_winrm_server(["Negotiate, Basic"], identify=False, ntlm=False))
    assert res is not None
    assert res["schemes"] == ["Negotiate", "Basic"]


def test_non_wsman_endpoint_is_none():
    assert _probe(_winrm_server([], plain=True)) is None


# --- check_exposure dispatch ------------------------------------------------
def _dispatch(server, svc):
    async def run():
        srv = await asyncio.start_server(server, "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())


def test_dispatch_basic_cleartext_is_alert():
    svc = Service(port=0, name="wsman", state="open")
    _dispatch(_winrm_server(["Negotiate", "Basic"]), svc)
    ids = {s["id"] for s in svc.scripts}
    assert "winrm-identify" in ids
    assert "winrm-auth-methods" in ids
    assert "winrm-ntlm-info" in ids
    assert "winrm-basic-cleartext" in ids
    assert "winrm-basic-cleartext" in fp.EXPOSURE_ALERT_IDS   # real misconfig
    assert svc.confidence == "high"
    assert svc.version == "10.0.17763"
    assert svc.product == "Microsoft WinRM"


def test_dispatch_negotiate_only_no_alert():
    svc = Service(port=0, name="wsman", state="open")
    _dispatch(_winrm_server(["Negotiate", "Kerberos"]), svc)
    ids = {s["id"] for s in svc.scripts}
    assert "winrm-auth-methods" in ids
    assert "winrm-basic-cleartext" not in ids
    assert "winrm-basic-tls" not in ids
    assert svc.confidence != "high"


def test_dispatch_basic_over_tls_is_informational(monkeypatch):
    # Basic offered, but transport is TLS (cert already grabbed) -> credentials
    # are protected in transit, so this is informational, not an alert.
    async def fake_probe(host, port, timeout, tls):
        return {"identify": {"vendor": "Microsoft Corporation"},
                "schemes": ["Negotiate", "Basic"], "server": "Microsoft-HTTPAPI/2.0",
                "ntlm": {}}
    monkeypatch.setattr(fp, "winrm_probe", fake_probe)
    svc = Service(port=5986, name="wsman", state="open", tls={"subject_cn": "dc01"})
    asyncio.run(fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                  "127.0.0.1", svc))
    ids = {s["id"] for s in svc.scripts}
    assert "winrm-basic-tls" in ids
    assert "winrm-basic-cleartext" not in ids
    assert svc.confidence != "high"
