"""Kerberos KDC posture (TCP 88, RFC 4120).

An unauthenticated AS-REQ with no pre-auth classifies each candidate principal
from the KDC reply -- KDC_ERR_PREAUTH_REQUIRED(25)/AS-REP = exists,
KDC_ERR_C_PRINCIPAL_UNKNOWN(6) = absent -- and an AS-REP returned without
pre-auth marks an AS-REP-roastable account (the only alert). No credentials are
ever sent. Loopback mock KDC only; no real Active Directory is contacted."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service

REALM = "TEST.LOCAL"


# --- message builders (reuse the module's DER primitives) ------------------
def _krb_error(code, realm=REALM):
    fields = (fp._der(0xA0, fp._ber_int(5))            # pvno
              + fp._der(0xA1, fp._ber_int(30))         # msg-type 30
              + fp._der(0xA4, fp._der(0x18, b"20240101000000Z"))  # stime [4]
              + fp._der(0xA5, fp._ber_int(0))          # susec [5]
              + fp._der(0xA6, fp._ber_int(code))       # error-code [6]
              + fp._der(0xA9, fp._der(0x1B, realm.encode())))     # realm [9]
    return fp._der(0x7E, fp._der(0x30, fields))


def _krb_as_rep(user, realm=REALM, etype=23, cipher=b"\xAB" * 40):
    enc = fp._der(0x30, fp._der(0xA0, fp._ber_int(etype))
                  + fp._der(0xA2, fp._der(0x04, cipher)))
    fields = (fp._der(0xA0, fp._ber_int(5))            # pvno
              + fp._der(0xA1, fp._ber_int(11))         # msg-type 11
              + fp._der(0xA3, fp._der(0x1B, realm.encode()))      # crealm [3]
              + fp._der(0xA4, fp._krb_principal(1, [user]))       # cname [4]
              + fp._der(0xA6, enc))                    # enc-part [6]
    return fp._der(0x6B, fp._der(0x30, fields))


def _req_cname(req: bytes) -> str:
    """Pull the AS-REQ client principal name so the mock can answer per-user."""
    for t, c in fp._krb_seq_fields(req):               # KDC-REQ fields
        if t != 0xA4:                                  # req-body [4]
            continue
        body = fp._ber_split(c)[0][1]
        for bt, bc in fp._ber_split(body):
            if bt != 0xA1:                             # cname [1]
                continue
            pn = fp._ber_split(bc)[0][1]
            for pt, pc in fp._ber_split(pn):
                if pt == 0xA1:                         # name-string [1]
                    seqof = fp._ber_split(pc)[0][1]
                    return fp._ber_split(seqof)[0][1].decode("latin-1")
    return ""


# --- mock KDC --------------------------------------------------------------
def _kdc_server(valid, roastable=(), *, wrong_realm=False):
    """Loopback TCP KDC. `valid` exist (PREAUTH_REQUIRED), `roastable` exist and
    return an AS-REP, everything else is C_PRINCIPAL_UNKNOWN."""
    async def handler(reader, writer):
        try:
            hdr = await asyncio.wait_for(reader.readexactly(4), timeout=2.0)
            n = int.from_bytes(hdr, "big")
            req = await asyncio.wait_for(reader.readexactly(n), timeout=2.0)
        except Exception:
            writer.close()
            return
        user = _req_cname(req)
        if wrong_realm:
            msg = _krb_error(68)                        # KDC_ERR_WRONG_REALM
        elif user in roastable:
            msg = _krb_as_rep(user)
        elif user in valid:
            msg = _krb_error(25)                        # PREAUTH_REQUIRED
        else:
            msg = _krb_error(6)                         # C_PRINCIPAL_UNKNOWN
        writer.write(len(msg).to_bytes(4, "big") + msg)
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _probe(server, realm=REALM, users=None):
    async def run():
        srv = await asyncio.start_server(server, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            kw = {"users": users} if users is not None else {}
            return await fp.kerberos_probe("127.0.0.1", port, 1.0, realm, **kw)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


# --- AS-REQ wire format -----------------------------------------------------
def test_as_req_is_application_10_and_no_padata():
    req = fp._krb_as_req("administrator", REALM)
    assert req[0] == 0x6A                               # [APPLICATION 10]
    tags = [t for t, _ in fp._krb_seq_fields(req)]
    assert tags == [0xA1, 0xA2, 0xA4]                   # pvno, msg-type, req-body
    # msg-type is 10 (AS-REQ); padata [3]/0xA3 is absent (no pre-auth)
    assert fp._krb_ctx_int(fp._krb_seq_fields(req), 0xA2) == 10
    assert 0xA3 not in tags


# --- probe classification ---------------------------------------------------
def test_user_enum_valid_vs_absent():
    res = _probe(_kdc_server(valid=["administrator", "guest"]),
                 users=["administrator", "nouser", "guest"])
    assert res is not None and res["is_kdc"] is True
    assert res["valid"] == ["administrator", "guest"]
    assert res["unknown"] == ["nouser"]
    assert res["roastable"] == []


def test_asrep_roastable_is_detected_with_hash():
    res = _probe(_kdc_server(valid=["guest"], roastable=["svc-sql"]),
                 users=["svc-sql", "guest", "nouser"])
    assert "svc-sql" in res["valid"]
    assert len(res["roastable"]) == 1
    r = res["roastable"][0]
    assert r["user"] == "svc-sql" and r["etype"] == 23
    assert r["hash"].startswith("$krb5asrep$23$svc-sql@TEST.LOCAL:")


def test_wrong_realm_stops_and_flags():
    res = _probe(_kdc_server(valid=[], wrong_realm=True),
                 users=["administrator", "guest"])
    assert res is not None and res["wrong_realm"] is True
    assert res["valid"] == [] and res["roastable"] == []


def test_non_kdc_port_is_none():
    async def silent(reader, writer):
        writer.close()
    assert _probe(silent) is None


# --- check_exposure dispatch ------------------------------------------------
def _dispatch(server, cfg_kwargs):
    svc = Service(port=0, name="kerberos-sec", state="open")

    async def run():
        srv = await asyncio.start_server(server, "127.0.0.1", 0)
        svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(**cfg_kwargs), "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    return svc


def test_dispatch_realm_from_flag_alerts_on_roastable():
    svc = _dispatch(_kdc_server(valid=["administrator"], roastable=["administrator"]),
                    {"target": "10.0.0.5", "timeout": 1.0, "realm": "TEST.LOCAL"})
    ids = {s["id"] for s in svc.scripts}
    assert "krb-kdc" in ids
    assert "krb-user-enum" in ids
    assert "krb-asrep-roastable" in ids
    assert "krb-asrep-roastable" in fp.EXPOSURE_ALERT_IDS
    assert svc.confidence == "high"


def test_dispatch_realm_autoderived_from_fqdn_target():
    # No --realm; realm derived from the dotted-FQDN target dc01.test.local.
    svc = _dispatch(_kdc_server(valid=["guest"]),
                    {"target": "dc01.test.local", "timeout": 1.0})
    ids = {s["id"] for s in svc.scripts}
    assert "krb-kdc" in ids
    assert "krb-asrep-roastable" not in ids             # none roastable


def test_dispatch_realm_derived_from_hyphenated_fqdn():
    # A hyphenated hostname is a valid FQDN (not an IP range) -> realm derived.
    svc = _dispatch(_kdc_server(valid=["guest"], roastable=["guest"]),
                    {"target": "dc-01.test.local", "timeout": 1.0})
    ids = {s["id"] for s in svc.scripts}
    assert "krb-kdc" in ids
    assert "krb-asrep-roastable" in ids


def test_dispatch_bare_ip_without_realm_is_skipped():
    svc = _dispatch(_kdc_server(valid=["administrator"]),
                    {"target": "10.0.0.5", "timeout": 1.0})
    assert svc.scripts == []                            # no realm -> no probe
