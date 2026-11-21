"""Discovery path-probes (Solr / WebLogic / Appwrite). The HTTP client is a
stub returning canned responses per path -- no network needed."""
import asyncio

from servicescan import fingerprint as fp
from servicescan.config import ScanConfig
from servicescan.models import Service


class _Resp:
    def __init__(self, status, text):
        self.status = status
        self.text = text
        self.ok = 200 <= status < 400


class _StubHTTP:
    """Maps a path -> _Resp; any other path is a 404."""
    def __init__(self, routes):
        self.routes = routes

    async def fetch(self, url, method="GET", read_body=True):
        path = url.split("://", 1)[1].split("/", 1)[1]
        path = "/" + path
        for p, resp in self.routes.items():
            if path.startswith(p):
                return resp
        return _Resp(404, "not found")


def _run(routes, svc=None):
    svc = svc or Service(port=8080, name="http", state="open")
    http = _StubHTTP(routes)
    cfg = ScanConfig(target="x", concurrency=5, timeout=5.0)
    asyncio.run(fp.run_discovery_probes(cfg, http, "10.0.0.9", [svc]))
    return svc


def test_solr_discovered_with_version():
    body = '{"lucene":{"solr-spec-version":"8.11.2"},"system":{}}'
    svc = _run({"/solr/admin/info/system": _Resp(200, body)})
    aux = {p[0]: p[1] for p in svc.aux}
    assert aux.get("Solr") == "8.11.2"
    assert any(s["id"] == "discovery-app" for s in svc.scripts)
    assert "discovery" in svc.sources


def test_weblogic_presence_only_no_version():
    body = "<html><title>Oracle WebLogic Server Administration Console</title></html>"
    svc = _run({"/console/login/LoginForm.jsp": _Resp(200, body)})
    aux = {p[0]: p[1] for p in svc.aux}
    assert "Oracle WebLogic Server" in aux
    assert aux["Oracle WebLogic Server"] == ""     # version-less (no CVE guess)


def test_weblogic_version_from_console_footer():
    # 12.x/14.x consoles disclose the exact build unauthenticated in the login
    # page footer; the probe must capture it (lab body from vulhub 12.2.1.3-2018).
    body = ('<html><body><p id="footerVersion">WebLogic Server Version: '
            '12.2.1.3.0</p></body></html>')
    svc = _run({"/console/login/LoginForm.jsp": _Resp(200, body)})
    aux = {p[0]: p[1] for p in svc.aux}
    assert aux.get("Oracle WebLogic Server") == "12.2.1.3"  # _norm_ver 4-part cap


def test_weblogic_console_version_promoted_to_primary():
    # nmap named the primary product WebLogic but version-less; the footer build
    # must promote onto svc.version so CVE lookup is version-scoped.
    svc = Service(port=7001, name="http", state="open",
                  product="Oracle WebLogic Server")
    body = '<p id="footerVersion">WebLogic Server Version: 12.2.1.3.0</p>'
    _run({"/console/login/LoginForm.jsp": _Resp(200, body)}, svc)
    assert svc.version == "12.2.1.3"
    assert svc.cve_skip is False


def test_appwrite_discovered_with_version():
    svc = _run({"/v1/health/version": _Resp(200, '{"version":"1.5.7"}')})
    aux = {p[0]: p[1] for p in svc.aux}
    assert aux.get("Appwrite") == "1.5.7"


def test_solr_version_promoted_to_primary_product():
    # nmap named the primary product "Apache Solr" with no version; the probe's
    # version must be promoted onto svc.version so the primary CVE lookup is
    # version-scoped (not a wildcard that pulls every Solr CVE).
    svc = Service(port=8983, name="http", state="open", product="Apache Solr")
    body = '{"lucene":{"solr-spec-version":"8.11.4"}}'
    _run({"/solr/admin/info/system": _Resp(200, body)}, svc)
    assert svc.version == "8.11.4"
    assert svc.cve_skip is False


def test_version_not_promoted_when_not_primary_product():
    # Solr behind a different primary product: aux gets it, svc.version does not
    svc = Service(port=8983, name="http", state="open", product="nginx",
                  version="1.25.0")
    body = '{"lucene":{"solr-spec-version":"8.11.4"}}'
    _run({"/solr/admin/info/system": _Resp(200, body)}, svc)
    assert svc.version == "1.25.0"              # unchanged
    assert ["Solr", "8.11.4"] in svc.aux        # recorded as aux instead


def test_weblogic_inherits_nmap_version_for_cve():
    # nmap identified the service as WebLogic with a version but under a product
    # string we don't map; the probe's correctly-named aux inherits that version
    # so it can CVE-correlate.
    svc = Service(port=7001, name="http", state="open",
                  product="Oracle WebLogic admin httpd", version="12.2.1.3")
    body = "<title>Oracle WebLogic Server Administration Console</title>"
    _run({"/console/login/LoginForm.jsp": _Resp(200, body)}, svc)
    aux = {p[0]: p[1] for p in svc.aux}
    assert aux.get("Oracle WebLogic Server") == "12.2.1.3"


def test_weblogic_no_inherit_when_token_absent():
    # a version on an unrelated product must NOT be adopted
    svc = Service(port=7001, name="http", state="open",
                  product="nginx", version="1.25.0")
    body = "<title>Oracle WebLogic Server Administration Console</title>"
    _run({"/console/login/LoginForm.jsp": _Resp(200, body)}, svc)
    aux = {p[0]: p[1] for p in svc.aux}
    assert aux.get("Oracle WebLogic Server") == ""


def test_generic_version_json_is_not_appwrite():
    # a different API that also returns {"version":...} but not the bare Appwrite
    # shape must NOT be mislabelled Appwrite
    svc = _run({"/v1/health/version": _Resp(200,
               '{"status":"ok","data":{"version":"2.0"}}')})
    assert not any(p[0] == "Appwrite" for p in svc.aux)


def test_no_match_leaves_service_untouched():
    svc = _run({})                                 # everything 404
    assert svc.aux == [] and svc.scripts == []


def test_non_web_service_skipped():
    svc = Service(port=22, name="ssh", state="open")
    _run({"/solr/admin/info/system": _Resp(200, '{"solr-spec-version":"9.0.0"}')},
         svc)
    assert svc.aux == []
