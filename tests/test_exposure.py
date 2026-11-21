import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


def _probe(handler, probe, timeout=0.5):
    """Serve `handler` on loopback, run `probe` against it, return the result."""
    async def run():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await probe("127.0.0.1", port, timeout)
        finally:
            server.close()
            await server.wait_closed()
    return asyncio.run(run())


def _responder(payload: bytes):
    async def handler(reader, writer):
        try:
            await reader.read(256)          # consume the probe request
        except Exception:
            pass
        writer.write(payload)
        await writer.drain()
        writer.close()
    return handler


# --- Redis -----------------------------------------------------------------
def test_redis_open_extracts_version():
    body = b"$120\r\n# Server\r\nredis_version:7.2.4\r\nos:Linux\r\n"
    assert _probe(_responder(body), fp.redis_probe) == ("open", "7.2.4")


def test_redis_auth_required():
    assert _probe(_responder(b"-NOAUTH Authentication required.\r\n"),
                  fp.redis_probe) == ("auth", "")


def test_redis_protected_mode_is_not_open():
    body = b"-DENIED Redis is running in protected mode\r\n"
    assert _probe(_responder(body), fp.redis_probe) == ("auth", "")


def test_redis_non_redis_is_none():
    assert _probe(_responder(b"SSH-2.0-OpenSSH_9.0\r\n"), fp.redis_probe) is None


# --- memcached --------------------------------------------------------------
def test_memcached_open_extracts_version():
    assert _probe(_responder(b"VERSION 1.6.21\r\n"),
                  fp.memcached_probe) == ("open", "1.6.21")


def test_memcached_sasl_error_is_auth():
    assert _probe(_responder(b"ERROR\r\n"), fp.memcached_probe) == ("auth", "")


# --- MongoDB ----------------------------------------------------------------
def test_mongo_listdb_message_is_wellformed():
    msg = fp._mongo_listdb_msg()
    # messageLength header must equal the real length, opcode must be OP_MSG
    import struct
    length, _req, _resp, opcode = struct.unpack("<iiii", msg[:16])
    assert length == len(msg)
    assert opcode == 2013
    assert b"listDatabases" in msg and b"admin" in msg


def test_mongo_open_when_listing_returns_databases():
    body = b"\x00" * 20 + b"databases" + b"\x00" * 8     # >=16 bytes, has marker
    assert _probe(_responder(body), fp.mongodb_probe) == ("open", "")


def test_mongo_auth_required():
    body = b"\x00" * 20 + b"not authorized on admin" + b"\x00"
    assert _probe(_responder(body), fp.mongodb_probe) == ("auth", "")


def test_mongo_short_or_unrelated_is_none():
    assert _probe(_responder(b"hi"), fp.mongodb_probe) is None


# --- check_exposure wiring --------------------------------------------------
def _check(svc, handler):
    """Point a service at a mock server on an ephemeral port and run the check."""
    async def run():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        svc.port = server.sockets[0].getsockname()[1]
        try:
            await fp.check_exposure(ScanConfig(target="x", timeout=0.5),
                                    "127.0.0.1", svc)
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(run())
    return svc


def test_check_exposure_marks_redis_unauth():
    # name triggers the redis branch regardless of (ephemeral) port
    svc = Service(port=0, name="redis", state="open")
    _check(svc, _responder(b"# Server\r\nredis_version:7.0.0\r\n"))
    ids = [sc["id"] for sc in svc.scripts]
    assert "redis-unauth" in ids
    assert svc.version == "7.0.0"
    assert "exposure" in svc.sources
    assert "UNAUTHENTICATED" in svc.extrainfo


def test_check_exposure_auth_does_not_flag_unauth():
    svc = Service(port=0, name="redis", state="open")
    _check(svc, _responder(b"-NOAUTH Authentication required.\r\n"))
    ids = [sc["id"] for sc in svc.scripts]
    assert "redis-unauth" not in ids
    assert "redis-auth" in ids


def test_check_exposure_ignores_unrelated_service():
    svc = Service(port=0, name="ssh", state="open")
    _check(svc, _responder(b"SSH-2.0-OpenSSH_9.0\r\n"))
    assert svc.scripts == []


# --- HTTP(S)-based stores ---------------------------------------------------
def _probe4(handler, probe, timeout=0.5):
    """Like _probe but for the HTTP probes whose signature is (h, p, t, tls)."""
    return _probe(handler, lambda h, p, t: probe(h, p, t, False), timeout)


def _resp(status_line: bytes, body: bytes = b"") -> bytes:
    return (b"HTTP/1.0 " + status_line + b"\r\n"
            b"Content-Type: application/json\r\nConnection: close\r\n\r\n" + body)


def _router(routes: dict, default: bytes = None):
    """HTTP handler that replies per request path (longest-prefix match)."""
    if default is None:
        default = _resp(b"404 Not Found", b"not found")
    keys = sorted(routes, key=len, reverse=True)

    async def handler(reader, writer):
        try:
            req = await reader.read(4096)
        except Exception:
            req = b""
        path = "/"
        try:
            path = req.split(b"\r\n", 1)[0].decode("latin-1").split(" ")[1]
        except Exception:
            pass
        resp = default
        for k in keys:
            if path == k or path.startswith(k):
                resp = routes[k]
                break
        writer.write(resp)
        await writer.drain()
        writer.close()
    return handler


# Elasticsearch
def test_elasticsearch_open_extracts_version():
    body = (b'{"name":"n1","cluster_name":"es","version":{"number":"8.11.1",'
            b'"lucene_version":"9.8.0"},"tagline":"You Know, for Search"}')
    assert _probe4(_router({"/": _resp(b"200 OK", body)}),
                   fp.elasticsearch_probe) == ("open", "8.11.1")


def test_elasticsearch_auth_required():
    assert _probe4(_router({"/": _resp(b"401 Unauthorized", b"")}),
                   fp.elasticsearch_probe) == ("auth", "")


def test_elasticsearch_non_es_is_none():
    assert _probe4(_router({"/": _resp(b"200 OK", b"<html>hi</html>")}),
                   fp.elasticsearch_probe) is None


# CouchDB (two requests: / then /_all_dbs)
def test_couchdb_open_when_all_dbs_listed():
    welcome = _resp(b"200 OK", b'{"couchdb":"Welcome","version":"3.3.3"}')
    alldbs = _resp(b"200 OK", b'["_users","_replicator","app"]')
    r = _probe4(_router({"/_all_dbs": alldbs, "/": welcome}), fp.couchdb_probe)
    assert r == ("open", "3.3.3")


def test_couchdb_auth_when_all_dbs_refused():
    welcome = _resp(b"200 OK", b'{"couchdb":"Welcome","version":"3.3.3"}')
    r = _probe4(_router({"/_all_dbs": _resp(b"401 Unauthorized", b""),
                         "/": welcome}), fp.couchdb_probe)
    assert r == ("auth", "")


# Docker Engine API
def test_docker_open_extracts_version():
    body = (b'{"Version":"24.0.7","ApiVersion":"1.43","GoVersion":"go1.20.10",'
            b'"Os":"linux"}')
    assert _probe4(_router({"/version": _resp(b"200 OK", body)}),
                   fp.docker_api_probe) == ("open", "24.0.7")


def test_docker_non_docker_is_none():
    assert _probe4(_router({"/version": _resp(b"200 OK", b'{"foo":1}')}),
                   fp.docker_api_probe) is None


# etcd
def test_etcd_open_when_v2_keys_readable():
    ver = _resp(b"200 OK", b'{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}')
    keys = _resp(b"200 OK", b'{"action":"get","node":{"key":"/","dir":true}}')
    r = _probe4(_router({"/v2/keys": keys, "/version": ver}), fp.etcd_probe)
    assert r == ("open", "3.5.9")


def test_etcd_v3_only_is_none():
    # /version answers but v2 keyspace is disabled (404) -> no claim
    ver = _resp(b"200 OK", b'{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}')
    r = _probe4(_router({"/version": ver}), fp.etcd_probe)   # /v2/keys -> 404
    assert r is None


# kubelet
def test_kubelet_open_when_pods_listed():
    body = b'{"kind":"PodList","apiVersion":"v1","items":[]}'
    assert _probe4(_router({"/pods": _resp(b"200 OK", body)}),
                   fp.kubelet_probe) == ("open", "")


def test_kubelet_auth_when_forbidden():
    assert _probe4(_router({"/pods": _resp(b"403 Forbidden", b"forbidden")}),
                   fp.kubelet_probe) == ("auth", "")


# check_exposure wiring (port-triggered) + the auth-id is not an alert
def test_check_exposure_marks_docker_api_unauth():
    svc = Service(port=0, name="docker", state="open")
    body = _resp(b"200 OK",
                 b'{"Version":"24.0.7","ApiVersion":"1.43","GoVersion":"go1","Os":"linux"}')
    _check(svc, _router({"/version": body}))
    assert "docker-api-unauth" in [sc["id"] for sc in svc.scripts]


def test_kubelet_auth_id_is_not_an_alert():
    svc = Service(port=0, name="kubelet", state="open")
    _check(svc, _router({"/pods": _resp(b"401 Unauthorized", b"")}))
    ids = [sc["id"] for sc in svc.scripts]
    assert "kubelet-anon" not in ids and "kubelet-auth" in ids
    assert "kubelet-auth" not in fp.EXPOSURE_ALERT_IDS
