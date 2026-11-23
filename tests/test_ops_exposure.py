import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


# --- HTTP mock helpers ------------------------------------------------------
def _http(status_line: bytes, body: bytes = b"", headers: dict | None = None) -> bytes:
    hdrs = {"Content-Type": "application/json", "Connection": "close"}
    hdrs.update(headers or {})
    head = b"HTTP/1.0 " + status_line + b"\r\n"
    for k, v in hdrs.items():
        head += k.encode() + b": " + v.encode() + b"\r\n"
    return head + b"\r\n" + body


def _router(routes: dict, default: bytes | None = None):
    if default is None:
        default = _http(b"404 Not Found", b"nope")
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


def _raw(payload: bytes):
    async def handler(reader, writer):
        try:
            await reader.read(256)
        except Exception:
            pass
        writer.write(payload)
        await writer.drain()
        writer.close()
    return handler


def _run(handler, coro_factory, timeout=0.5):
    async def run():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await coro_factory("127.0.0.1", port, timeout)
        finally:
            server.close()
            await server.wait_closed()
    return asyncio.run(run())


def _http_probe(handler, probe, timeout=0.5):
    return _run(handler, lambda h, p, t: probe(h, p, t, False), timeout)


# --- Prometheus -------------------------------------------------------------
def test_prometheus_open_with_version():
    routes = {"/-/healthy": _http(b"200 OK", b"Prometheus Server is Healthy.\n"),
              "/api/v1/status/buildinfo":
                  _http(b"200 OK",
                        b'{"status":"success","data":{"version":"2.45.0",'
                        b'"goVersion":"go1.20"}}')}
    assert _http_probe(_router(routes), fp.prometheus_probe) == ("open", "2.45.0")


def test_prometheus_auth_when_protected():
    assert _http_probe(_router({"/-/healthy": _http(b"401 Unauthorized")}),
                       fp.prometheus_probe) == ("auth", "")


def test_prometheus_none_when_not_prometheus():
    assert _http_probe(_router({"/-/healthy": _http(b"200 OK", b"OK")}),
                       fp.prometheus_probe) is None


# --- Consul -----------------------------------------------------------------
def test_consul_open_extracts_version():
    body = (b'{"Config":{"Datacenter":"dc1","Version":"1.17.1"},'
            b'"Member":{"Name":"n1"}}')
    assert _http_probe(_router({"/v1/agent/self": _http(b"200 OK", body)}),
                       fp.consul_probe) == ("open", "1.17.1")


def test_consul_auth_when_acls_enabled():
    assert _http_probe(_router({"/v1/agent/self":
                                _http(b"403 Forbidden", b"Permission denied")}),
                       fp.consul_probe) == ("auth", "")


def test_consul_none_when_not_consul():
    assert _http_probe(_router({"/v1/agent/self": _http(b"200 OK", b'{"x":1}')}),
                       fp.consul_probe) is None


# --- Vault (informational) --------------------------------------------------
def test_vault_unsealed():
    body = b'{"type":"shamir","sealed":false,"version":"1.15.2","t":1,"n":1}'
    r = _http_probe(_router({"/v1/sys/seal-status": _http(b"200 OK", body)}),
                    fp.vault_probe)
    assert r == {"sealed": False, "version": "1.15.2"}


def test_vault_sealed():
    body = b'{"type":"shamir","sealed":true,"version":"1.15.2"}'
    r = _http_probe(_router({"/v1/sys/seal-status": _http(b"200 OK", body)}),
                    fp.vault_probe)
    assert r["sealed"] is True


def test_vault_none_when_not_vault():
    assert _http_probe(_router({"/v1/sys/seal-status": _http(b"200 OK", b"{}")}),
                       fp.vault_probe) is None


# --- RabbitMQ ---------------------------------------------------------------
def test_rabbitmq_open_unauth_overview():
    body = b'{"management_version":"3.12.0","rabbitmq_version":"3.12.0"}'
    assert _http_probe(_router({"/api/overview": _http(b"200 OK", body)}),
                       fp.rabbitmq_probe) == ("open", "3.12.0")


def test_rabbitmq_auth_when_realm_present():
    resp = _http(b"401 Unauthorized", b"",
                 {"WWW-Authenticate": 'Basic realm="RabbitMQ Management"'})
    assert _http_probe(_router({"/api/overview": resp}),
                       fp.rabbitmq_probe) == ("auth", "")


def test_rabbitmq_none_for_unrelated_401():
    resp = _http(b"401 Unauthorized", b"", {"WWW-Authenticate": 'Basic realm="x"'})
    assert _http_probe(_router({"/api/overview": resp}), fp.rabbitmq_probe) is None


# --- MinIO ------------------------------------------------------------------
def test_minio_anonymous_listing_is_open():
    routes = {
        "/minio/health/live": _http(b"200 OK", b"", {"Server": "MinIO"}),
        "/": _http(b"200 OK",
                   b'<?xml version="1.0"?><ListAllMyBucketsResult><Buckets/>'
                   b'</ListAllMyBucketsResult>', {"Server": "MinIO"}),
    }
    assert _http_probe(_router(routes), fp.minio_probe) == ("open", "")


def test_minio_present_but_listing_denied_is_auth():
    routes = {
        "/minio/health/live": _http(b"200 OK", b"", {"Server": "MinIO"}),
        "/": _http(b"403 Forbidden",
                   b"<Error><Code>AccessDenied</Code></Error>", {"Server": "MinIO"}),
    }
    assert _http_probe(_router(routes), fp.minio_probe) == ("auth", "")


def test_minio_none_when_not_minio():
    routes = {"/minio/health/live": _http(b"404 Not Found", b""),
              "/": _http(b"200 OK", b"<html>hi</html>", {"Server": "nginx"})}
    assert _http_probe(_router(routes), fp.minio_probe) is None


# --- Portainer --------------------------------------------------------------
def test_portainer_uninitialised_is_open():
    routes = {"/api/system/status": _http(b"200 OK", b'{"Version":"2.19.4"}'),
              "/api/users/admin/check": _http(b"404 Not Found", b"")}
    assert _http_probe(_router(routes), fp.portainer_probe) == ("open", "2.19.4")


def test_portainer_initialised_is_auth():
    routes = {"/api/system/status": _http(b"200 OK", b'{"Version":"2.19.4"}'),
              "/api/users/admin/check": _http(b"204 No Content", b"")}
    assert _http_probe(_router(routes), fp.portainer_probe) == ("auth", "2.19.4")


def test_portainer_none_when_no_status_endpoint():
    assert _http_probe(_router({}), fp.portainer_probe) is None


# --- ZooKeeper (raw TCP 4lw) ------------------------------------------------
def test_zookeeper_open_extracts_version():
    body = (b"Zookeeper version: 3.8.3-6ad6d364c7c0bcf0de452d54ebefa3058098ab56\n"
            b"Clients:\n /10.0.0.5:5321[1]\nMode: standalone\n")
    assert _run(_raw(body), fp.zookeeper_probe) == ("open", "3.8.3")


def test_zookeeper_whitelist_restricted_is_auth():
    body = b"stat is not executed because it is not in the whitelist.\n"
    assert _run(_raw(body), fp.zookeeper_probe) == ("auth", "")


def test_zookeeper_none_when_unrelated():
    assert _run(_raw(b"SSH-2.0-OpenSSH_9.0\r\n"), fp.zookeeper_probe) is None


# --- check_exposure dispatch (name-triggered on an ephemeral port) ----------
def _check(name, handler, tls=False):
    svc = Service(port=0, name=name, state="open", tls=tls)

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


def test_dispatch_marks_prometheus_unauth():
    routes = {"/-/healthy": _http(b"200 OK", b"Prometheus Server is Healthy.\n"),
              "/api/v1/status/buildinfo":
                  _http(b"200 OK", b'{"data":{"version":"2.45.0"}}')}
    svc = _check("prometheus", _router(routes))
    ids = {sc["id"] for sc in svc.scripts}
    assert "prometheus-unauth" in ids
    assert svc.version == "2.45.0"
    assert "UNAUTHENTICATED" in svc.extrainfo


def test_dispatch_consul_auth_is_not_an_alert():
    svc = _check("consul", _router({"/v1/agent/self":
                                     _http(b"403 Forbidden", b"denied")}))
    ids = {sc["id"] for sc in svc.scripts}
    assert ids == {"consul-auth"}
    assert "consul-auth" not in fp.EXPOSURE_ALERT_IDS


def test_dispatch_vault_is_informational_not_alert():
    body = b'{"type":"shamir","sealed":false,"version":"1.15.2"}'
    svc = _check("vault", _router({"/v1/sys/seal-status": _http(b"200 OK", body)}))
    ids = {sc["id"] for sc in svc.scripts}
    assert ids == {"vault-exposed"}
    assert "vault-exposed" not in fp.EXPOSURE_ALERT_IDS
    assert svc.version == "1.15.2"
    assert "UNSEALED" in svc.scripts[0]["output"]


def test_dispatch_marks_zookeeper_unauth():
    body = b"Zookeeper version: 3.8.3-x\nMode: standalone\n"
    svc = _check("zookeeper", _raw(body))
    assert "zookeeper-unauth" in {sc["id"] for sc in svc.scripts}
    assert svc.version == "3.8.3"


def test_dispatch_portainer_uninit_is_alert():
    routes = {"/api/system/status": _http(b"200 OK", b'{"Version":"2.19.4"}'),
              "/api/users/admin/check": _http(b"404 Not Found", b"")}
    svc = _check("portainer", _router(routes))
    assert "portainer-unauth" in {sc["id"] for sc in svc.scripts}


# --- Server-header router: catch an ops product on a non-standard port -------
# nmap fingerprints MinIO on a custom port only as a generic "golang net/http"
# server, so svc.name is "http" and the name/port-gated minio branch never
# fires. The Server-header sniff at the top of check_exposure must fold "minio"
# into the name so the probe still runs.
def test_dispatch_minio_detected_via_server_header_on_generic_name():
    routes = {
        "/minio/health/live": _http(b"200 OK", b"", {"Server": "MinIO"}),
        "/": _http(b"200 OK", b"<ListAllMyBucketsResult/>", {"Server": "MinIO"}),
    }
    svc = _check("http", _router(routes))      # generic nmap name, no "minio"
    assert "minio-unauth" in {sc["id"] for sc in svc.scripts}


def test_server_header_router_does_not_misroute_generic_go_server():
    # A plain Go net/http server (no self-identifying Server token) must not be
    # routed to any ops probe.
    routes = {"/": _http(b"200 OK", b"hello", {"Server": "Go-http-server/1.1"})}
    svc = _check("http", _router(routes))
    assert not any(t in sc["id"]
                   for sc in svc.scripts
                   for t in fp._SERVER_HEADER_PRODUCT_TOKENS)


def test_http_server_product_hint_reads_server_token():
    routes = {"/": _http(b"403 Forbidden", b"", {"Server": "MinIO"})}
    hint = _run(_router(routes),
                lambda h, p, t: fp._http_server_product_hint(h, p, t, False))
    assert hint == "minio"
