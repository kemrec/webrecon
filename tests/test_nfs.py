"""NFS / rpcbind exposure (TCP 111). Dependency-free ONC RPC: portmap DUMP
(proc 4) enumerates RPC programs, mountd EXPORT (proc 5) lists NFS exports; a
world-shared export is an unauthenticated data-exposure alert. Read-only query
procedures only. Loopback only."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


# --- XDR builders for the mock RPC replies ----------------------------------
def _xdrs(s: str) -> bytes:
    b = s.encode()
    return len(b).to_bytes(4, "big") + b + b"\x00" * ((4 - len(b) % 4) % 4)


def _entry(prog, vers, prot, port) -> bytes:
    return ((1).to_bytes(4, "big") + prog.to_bytes(4, "big")
            + vers.to_bytes(4, "big") + prot.to_bytes(4, "big")
            + port.to_bytes(4, "big"))


def _mk_dump(mport: int, with_mountd: bool) -> bytes:
    e = _entry(100000, 2, 6, 111) + _entry(100003, 3, 6, 2049)
    if with_mountd:
        e += _entry(100005, 3, 6, mport)
    return e + (0).to_bytes(4, "big")


def _export(dirp: str, groups) -> bytes:
    out = (1).to_bytes(4, "big") + _xdrs(dirp)
    for g in groups:
        out += (1).to_bytes(4, "big") + _xdrs(g)
    return out + (0).to_bytes(4, "big")


def _mk_exports(mode: str) -> bytes:
    if mode == "world":
        body = _export("/srv/public", []) + _export("/home", ["10.0.0.0/24"])
    else:  # restricted
        body = _export("/data", ["192.168.1.0/24"])
    return body + (0).to_bytes(4, "big")


# --- parser units -----------------------------------------------------------
def test_parse_rpcb_dump():
    data = _mk_dump(635, True)
    progs = fp._parse_rpcb_dump(data, 0)
    assert (100005, 3, 6, 635) in progs
    assert (100003, 3, 6, 2049) in progs


def test_parse_mount_exports_world_and_restricted():
    ex = fp._parse_mount_exports(_mk_exports("world"), 0)
    assert ex == [("/srv/public", []), ("/home", ["10.0.0.0/24"])]


# --- mock rpcbind + mountd (same TCP port) ----------------------------------
def _rpc_server(mode: str, holder: list):
    async def handler(reader, writer):
        try:
            mark = await asyncio.wait_for(reader.readexactly(4), timeout=2.0)
            n = int.from_bytes(mark, "big") & 0x7fffffff
            call = await asyncio.wait_for(reader.readexactly(n), timeout=2.0)
        except Exception:
            writer.close()
            return
        xid = call[0:4]
        prog = int.from_bytes(call[12:16], "big")
        proc = int.from_bytes(call[20:24], "big")
        if mode == "notrpc":
            writer.write(b"\x00\x00\x00\x08garbage!")
            await writer.drain()
            writer.close()
            return
        hdr = (xid + (1).to_bytes(4, "big") + (0).to_bytes(4, "big")
               + b"\x00" * 8 + (0).to_bytes(4, "big"))
        if prog == 100000 and proc == 4:
            body = _mk_dump(holder[0], mode != "nomountd")
        elif prog == 100005 and proc == 5:
            body = _mk_exports("world" if mode == "world" else "restricted")
        else:
            body = b""
        reply = hdr + body
        writer.write((0x80000000 | len(reply)).to_bytes(4, "big") + reply)
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


def _probe(mode, timeout=1.0):
    holder = [0]

    async def run():
        srv = await asyncio.start_server(_rpc_server(mode, holder), "127.0.0.1", 0)
        holder[0] = srv.sockets[0].getsockname()[1]
        try:
            return await fp.nfs_probe("127.0.0.1", holder[0], timeout)
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(run())


def test_probe_world_export():
    r = _probe("world")
    assert r is not None
    assert ("/srv/public", []) in r["exports"]
    assert any(pg == 100005 for pg, v, pr, pt in r["programs"])


def test_probe_restricted_export():
    r = _probe("restricted")
    assert r["exports"] == [("/data", ["192.168.1.0/24"])]


def test_probe_no_mountd_lists_programs_only():
    r = _probe("nomountd")
    assert r is not None and r["exports"] == []
    assert any(pg == 100003 for pg, v, pr, pt in r["programs"])


def test_probe_non_rpc_is_none():
    assert _probe("notrpc") is None


# --- check_exposure dispatch ------------------------------------------------
def _check(mode, name="rpcbind"):
    svc = Service(port=0, name=name, state="open")
    holder = [0]

    async def run():
        srv = await asyncio.start_server(_rpc_server(mode, holder), "127.0.0.1", 0)
        holder[0] = svc.port = srv.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=1.0),
                                    "127.0.0.1", svc)
        finally:
            srv.close()
            await srv.wait_closed()
    asyncio.run(run())
    return svc


def test_dispatch_world_export_is_alert():
    svc = _check("world")
    ids = {s["id"] for s in svc.scripts}
    assert "nfs-export-world" in ids
    assert "nfs-export-world" in fp.EXPOSURE_ALERT_IDS
    assert "rpcbind-dump" in ids and "nfs-exports" in ids
    assert "rpcbind-dump" not in fp.EXPOSURE_ALERT_IDS


def test_dispatch_restricted_is_informational():
    svc = _check("restricted")
    ids = {s["id"] for s in svc.scripts}
    assert "nfs-exports" in ids
    assert "nfs-export-world" not in ids          # no world export -> no alert
