"""RTSP recon (OPTIONS/DESCRIBE unauth + auth detection + default-cred test).
A loopback RTSP server speaks canned replies per mode -- no camera, no network
beyond 127.0.0.1. Each _rtsp_request reconnects, so one request per connection."""
import asyncio
import base64
import hashlib
import ssl

import pytest

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service

_SDP = ("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=Test\r\n"
        "m=video 0 RTP/AVP 96\r\n")


def _resp(code, phrase, cseq, extra="", body=""):
    lines = [f"RTSP/1.0 {code} {phrase}", f"CSeq: {cseq}", "Server: TestCam/1.0"]
    if extra:
        lines.append(extra)
    if body:
        lines.append("Content-Type: application/sdp")
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


def _good_digest(user, pw, realm, nonce, method, uri):
    h = lambda s: hashlib.md5(s.encode()).hexdigest()  # noqa: E731
    return h(f"{h(f'{user}:{realm}:{pw}')}:{nonce}:{h(f'{method}:{uri}')}")


def _make_server(mode):
    """mode: 'unauth' | 'basic' | 'digest' | 'locked' (auth, no default works)."""
    realm, nonce = "CamRealm", "abc123nonce"

    def describe(hdrs, cseq, uri):
        auth = hdrs.get("authorization", "")
        if mode == "unauth":
            return _resp(200, "OK", cseq, body=_SDP)
        if mode == "pathonly":
            # an open stream only on an extra (non-root) path; base is gated
            if uri.endswith("/h264Preview_01_main"):
                return _resp(200, "OK", cseq, body=_SDP)
            return _resp(401, "Unauthorized", cseq,
                         'WWW-Authenticate: Basic realm="r"')
        if mode == "basic":
            want = "Basic " + base64.b64encode(b"admin:admin").decode()
            if auth == want:
                return _resp(200, "OK", cseq, body=_SDP)
            return _resp(401, "Unauthorized", cseq,
                         f'WWW-Authenticate: Basic realm="{realm}"')
        if mode == "digest":
            if auth.startswith("Digest") and f'response="{_good_digest("admin","admin",realm,nonce,"DESCRIBE",uri)}"' in auth:
                return _resp(200, "OK", cseq, body=_SDP)
            return _resp(401, "Unauthorized", cseq,
                         f'WWW-Authenticate: Digest realm="{realm}", nonce="{nonce}"')
        # locked: always 401 (no credential in the default list is accepted)
        return _resp(401, "Unauthorized", cseq,
                     f'WWW-Authenticate: Digest realm="{realm}", nonce="{nonce}"')

    async def handler(reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
        except Exception:
            data = b""
        text = data.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        method = first.split(" ", 1)[0] if first else ""
        uri = first.split(" ")[1] if len(first.split(" ")) > 1 else ""
        hdrs = {}
        for ln in text.split("\r\n")[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        cseq = hdrs.get("cseq", "1")
        if method == "OPTIONS":
            out = _resp(200, "OK", cseq, "Public: OPTIONS, DESCRIBE, SETUP, PLAY")
        elif method == "DESCRIBE":
            out = describe(hdrs, cseq, uri)
        else:
            out = _resp(405, "Method Not Allowed", cseq)
        try:
            writer.write(out)
            await writer.drain()
        except Exception:
            pass
        writer.close()

    return handler


def _run_check(mode, cam_creds=True):
    async def run():
        server = await asyncio.start_server(_make_server(mode), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        svc = Service(port=port, name="rtsp", state="open")
        cfg = ScanConfig(target="x", timeout=2.0, concurrency=5,
                         cam_creds=cam_creds)
        try:
            await fp.check_exposure(cfg, "127.0.0.1", svc)
        finally:
            server.close()
            await server.wait_closed()
        return svc
    return asyncio.run(run())


def _ids(svc):
    return {s["id"] for s in svc.scripts}


def test_parse_www_auth_basic_and_digest():
    assert fp._parse_www_auth('Basic realm="X"')[:2] == ("Basic", "X")
    sc, realm, nonce, qop = fp._parse_www_auth(
        'Digest realm="R", nonce="N", qop="auth"')
    assert (sc, realm, nonce, qop) == ("Digest", "R", "N", "auth")


def test_rtsp_auth_header_digest_matches_reference():
    uri = "rtsp://h:554/"
    hdr = fp._rtsp_auth_header("Digest", "R", "N", "", "admin", "admin",
                               "DESCRIBE", uri)
    assert f'response="{_good_digest("admin","admin","R","N","DESCRIBE",uri)}"' in hdr


def test_rtsp_unauthenticated_stream_is_critical():
    svc = _run_check("unauth")
    assert "rtsp-unauth" in _ids(svc)
    assert "rtsp-unauth" in fp.EXPOSURE_ALERT_IDS
    assert svc.confidence == "high"


def test_rtsp_basic_default_creds_detected():
    svc = _run_check("basic")
    assert "rtsp-auth" in _ids(svc)                 # 401 scheme recorded
    assert "rtsp-default-creds" in _ids(svc)        # admin:admin accepted
    assert "admin:admin" in svc.extrainfo


def test_rtsp_digest_default_creds_detected():
    svc = _run_check("digest")
    assert "rtsp-default-creds" in _ids(svc)
    assert "admin:admin" in svc.extrainfo


def test_rtsp_locked_reports_auth_only():
    svc = _run_check("locked")
    assert "rtsp-auth" in _ids(svc)
    assert "rtsp-default-creds" not in _ids(svc)    # no default credential works


def test_rtsp_creds_flag_off_skips_active_step():
    svc = _run_check("basic", cam_creds=False)
    assert "rtsp-auth" in _ids(svc)
    assert "rtsp-default-creds" not in _ids(svc)     # --no-rtsp-creds honored


def test_extra_describe_paths_registered():
    for p in ("/h264Preview_01_main", "/videoMain", "/profile1",
              "/video1", "/ch01.264"):
        assert p in fp._RTSP_DESCRIBE_PATHS


def test_rtsp_stream_found_on_extra_path():
    # base "/" is gated (401); the open stream is only on a newly-added path,
    # so the DESCRIBE loop must reach it to find the unauth stream.
    svc = _run_check("pathonly")
    assert "rtsp-unauth" in _ids(svc)
    assert svc.confidence == "high"


def test_rtsp_port_322_selects_tls(monkeypatch):
    # port 322 (RTSPS) must drive the probe over TLS and label the service rtsps
    seen = {}

    async def fake_probe(host, port, timeout, tls=False):
        seen["tls"] = tls
        return {"server": "", "public": "", "unauth": True, "unauth_path": "/s",
                "auth": "", "realm": "", "nonce": "", "qop": "", "auth_path": "/"}

    monkeypatch.setattr(fp, "rtsp_probe", fake_probe)

    async def run():
        svc = Service(port=322, name="", state="open")
        cfg = ScanConfig(target="x", timeout=1.0, concurrency=5)
        await fp.check_exposure(cfg, "127.0.0.1", svc)
        return svc

    svc = asyncio.run(run())
    assert seen["tls"] is True
    assert svc.name == "rtsps"
    assert "RTSPS" in svc.extrainfo


def _selfsigned():
    cryptography = pytest.importorskip("cryptography")
    import datetime
    import os
    import tempfile
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    # a SAN that exists ONLY in the cert -- the internal vhost the pivot surfaces
    san = x509.SubjectAlternativeName([x509.DNSName("cam.internal.local")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    return cp, kp


def test_rtsps_tls_unauthenticated_stream_end_to_end():
    # a real TLS-wrapped RTSP server: the TLS transport must be negotiated and
    # the RTSP recon must then work exactly as it does in plaintext.
    cp, kp = _selfsigned()

    async def run():
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(cp, kp)
        server = await asyncio.start_server(_make_server("unauth"),
                                            "127.0.0.1", 0, ssl=sctx)
        port = server.sockets[0].getsockname()[1]
        svc = Service(port=port, name="rtsps", state="open")
        cfg = ScanConfig(target="x", timeout=3.0, concurrency=5)
        try:
            await fp.check_exposure(cfg, "127.0.0.1", svc)
        finally:
            server.close()
            await server.wait_closed()
        return svc

    svc = asyncio.run(run())
    assert "rtsp-unauth" in _ids(svc)
    assert svc.name == "rtsps"
    assert "RTSPS" in svc.extrainfo
    # RTSPS cert/SAN pivot: the cert was grabbed onto svc.tls and surfaced
    assert "rtsps-cert" in _ids(svc)
    assert "cam.internal.local" in svc.tls.get("sans", [])
    out = {s["id"]: s["output"] for s in svc.scripts}
    assert "cam.internal.local" in out["rtsps-cert"]
    # and the web-chain SAN harvester picks that cert-only name up for the pivot
    from servicescan import chain
    assert "cam.internal.local" in chain.harvest_sans([svc])


def test_non_rtsp_port_emits_nothing():
    # a plain TCP echo-ish server that never speaks RTSP must not be labelled
    async def run():
        async def handler(reader, writer):
            try:
                await reader.read(64)
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
            writer.close()
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        svc = Service(port=port, name="rtsp", state="open")
        cfg = ScanConfig(target="x", timeout=2.0, concurrency=5)
        try:
            await fp.check_exposure(cfg, "127.0.0.1", svc)
        finally:
            server.close()
            await server.wait_closed()
        return svc
    svc = asyncio.run(run())
    assert not any(i.startswith("rtsp") for i in _ids(svc))
