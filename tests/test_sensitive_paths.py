"""Tests for the content-verified sensitive-path probe.

Every check must (a) fire on a body carrying its signature and (b) stay silent
on a 200 that lacks it -- especially an SPA/soft-404 app shell, which is the
dominant false-positive source. These credential-shaped strings are DELIBERATE
TEST FIXTURES for the signature matcher, not real secrets.
"""
import asyncio
import json
from dataclasses import dataclass, field

from webrecon import probes


# --- fake HTTP client -------------------------------------------------------
@dataclass
class _Resp:
    status: int
    text: str = ""
    content_type: str = "text/plain"
    final_url: str = ""
    headers: dict = field(default_factory=dict)
    ok: bool = True
    error: str | None = None
    raw: bytes = b""

    def __post_init__(self):
        if not self.raw and self.text:
            self.raw = self.text.encode("utf-8", "replace")[:8192]


class _FakeHTTP:
    """Serves a path->Response routing table; anything unmapped is a 404."""
    def __init__(self, routes: dict):
        self.routes = routes
        self.requested = []

    async def fetch(self, url, *a, **k):
        self.requested.append(url)
        from urllib.parse import urlsplit
        path = urlsplit(url).path
        r = self.routes.get(path)
        if r is None:
            return _Resp(404, "not found", final_url=url)
        r.final_url = url
        return r


def _run(coro):
    return asyncio.run(coro)


def _probe(routes: dict):
    http = _FakeHTTP(routes)
    findings = _run(probes.probe_sensitive_paths(http, "http://t.local:8080/"))
    return {f["type"]: f for f in findings}, http


# --- per-signature hit tests ------------------------------------------------
def test_git_config_hit():
    body = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
    found, _ = _probe({"/.git/config": _Resp(200, body)})
    assert "vcs-git" in found
    assert found["vcs-git"]["severity"] == "high"
    assert found["vcs-git"]["url"] == "http://t.local:8080/.git/config"


def test_git_head_hit_when_no_config():
    found, _ = _probe({"/.git/HEAD": _Resp(200, "ref: refs/heads/main\n")})
    assert "vcs-git" in found


def test_svn_entries_hit():
    body = "12\n\ndir\n\nhttps://svn.example/repo\n"
    found, _ = _probe({"/.svn/entries": _Resp(200, body)})
    assert found["vcs-svn"]["severity"] == "medium"


def test_hg_requires_hit():
    found, _ = _probe({"/.hg/requires": _Resp(200, "revlogv1\nstore\nfncache\n")})
    assert "vcs-hg" in found


def test_actuator_index_hit():
    body = json.dumps({"_links": {"self": {"href": "/actuator"},
                                  "health": {"href": "/actuator/health"}}})
    found, _ = _probe({"/actuator": _Resp(200, body, "application/json")})
    assert found["actuator"]["severity"] == "medium"


def test_actuator_env_hit():
    body = json.dumps({"activeProfiles": ["prod"], "propertySources": []})
    found, _ = _probe({"/actuator/env": _Resp(200, body, "application/json")})
    assert found["actuator-env"]["severity"] == "high"


def test_actuator_heapdump_via_links():
    body = json.dumps({"_links": {
        "self": {"href": "http://t.local:8080/actuator"},
        "heapdump": {"href": "http://t.local:8080/actuator/heapdump"}}})
    found, _ = _probe({"/actuator": _Resp(200, body, "application/json")})
    assert "actuator-heapdump" in found
    assert found["actuator-heapdump"]["severity"] == "high"
    assert found["actuator-heapdump"]["path"] == "/actuator/heapdump"


def test_env_file_hit():
    body = "APP_ENV=production\nAPP_KEY=base64:ZmFrZXRlc3RrZXk=\nDB_PASSWORD=hunter2\n"
    found, _ = _probe({"/.env": _Resp(200, body)})
    assert found["dotenv"]["severity"] == "high"


def test_htpasswd_hit():
    body = "admin:$apr1$abcd$Zc.fakehashfortest/\nbob:$2y$10$fakebcrypttestvalue\n"
    found, _ = _probe({"/.htpasswd": _Resp(200, body)})
    assert found["htpasswd"]["severity"] == "high"


def test_webconfig_hit():
    body = ('<?xml version="1.0"?>\n<configuration>\n  <system.web>\n'
            '    <compilation debug="true"/>\n  </system.web>\n</configuration>')
    found, _ = _probe({"/web.config": _Resp(200, body, "text/xml")})
    assert found["iis-webconfig"]["severity"] == "high"


def test_ds_store_hit_binary_magic():
    raw = b"\x00\x00\x00\x01Bud1\x00\x00\x00\x00" + b"\x00" * 32
    found, _ = _probe({"/.DS_Store": _Resp(200, "", "application/octet-stream",
                                           raw=raw)})
    assert found["ds-store"]["severity"] == "low"


def test_server_status_hit():
    body = "<html><head><title>Apache Status</title></head><body>" \
           "<h1>Apache Server Status for t.local</h1></body></html>"
    found, _ = _probe({"/server-status": _Resp(200, body, "text/html")})
    assert "apache-status" in found


def test_pprof_hit():
    body = ("<html><body>/debug/pprof/<br>Types of profiles available:<br>"
            "<a href='goroutine'>goroutine</a></body></html>")
    found, _ = _probe({"/debug/pprof/": _Resp(200, body, "text/html")})
    assert "go-pprof" in found


def test_prometheus_metrics_hit():
    body = "# HELP go_goroutines Number of goroutines.\n" \
           "# TYPE go_goroutines gauge\ngo_goroutines 42\n"
    found, _ = _probe({"/metrics": _Resp(200, body)})
    assert found["prometheus"]["severity"] == "low"


def test_elasticsearch_hit():
    body = json.dumps({"cluster_name": "docker-cluster", "status": "green",
                       "number_of_nodes": 1})
    found, _ = _probe({"/_cluster/health": _Resp(200, body, "application/json")})
    assert found["elasticsearch"]["severity"] == "high"


def test_couchdb_hit():
    found, _ = _probe({"/_all_dbs": _Resp(
        200, '["_users","_replicator","mydb"]', "application/json")})
    assert found["couchdb"]["severity"] == "high"


def test_kibana_hit():
    body = json.dumps({"name": "kibana", "version": {"number": "7.10.0"},
                       "status": {"overall": {"state": "green"}}})
    found, _ = _probe({"/api/status": _Resp(200, body, "application/json")})
    assert "kibana" in found


def test_autoindex_hit():
    body = ("<html><head><title>Index of /uploads</title></head><body>"
            "<h1>Index of /uploads</h1><a href='../'>Parent Directory</a>"
            "<a href='a.txt'>a.txt</a></body></html>")
    found, _ = _probe({"/uploads/": _Resp(200, body, "text/html")})
    assert found["dir-listing"]["severity"] == "medium"
    assert found["dir-listing"]["path"] == "/uploads/"


# --- false-positive guards --------------------------------------------------
_SPA = _Resp(200, "<!doctype html><html><head><title>App</title></head>"
                  "<body><div id='root'></div></body></html>", "text/html")


def test_spa_catch_all_yields_nothing():
    """A SPA that returns its index.html (200) for every path must not trip any
    non-HTML check -- this is the core false-positive guard."""
    routes = {p: _SPA for p in (
        "/.git/config", "/.git/HEAD", "/.svn/entries", "/.hg/requires",
        "/actuator", "/actuator/env", "/actuator/mappings", "/.env",
        "/.htpasswd", "/web.config", "/_cluster/health", "/_all_dbs",
        "/api/status", "/metrics")}
    found, _ = _probe(routes)
    assert found == {}


def test_404_everywhere_yields_nothing():
    found, _ = _probe({})
    assert found == {}


def test_git_config_wrong_body_no_fp():
    # a 200 without the [core]/repositoryformatversion signature -> silent
    found, _ = _probe({"/.git/config": _Resp(200, "just some unrelated text")})
    assert "vcs-git" not in found


def test_env_requires_known_key_no_fp():
    # generic text with an '=' but no recognised env key -> no finding
    found, _ = _probe({"/.env": _Resp(200, "hello = world\nfoo = bar\n")})
    assert "dotenv" not in found


def test_couchdb_generic_array_no_fp():
    # a plain JSON array that is not the couch system-db list -> silent
    found, _ = _probe({"/_all_dbs": _Resp(200, '["alpha","beta"]',
                                          "application/json")})
    assert "couchdb" not in found


def test_autoindex_requires_parent_link_no_fp():
    # prose mentioning "Index of /" but no parent/entry link -> not an autoindex
    body = "<html><body><p>Index of / is disabled on this server.</p></body></html>"
    found, _ = _probe({"/": _Resp(200, body, "text/html")})
    assert "dir-listing" not in found


def test_non_200_no_fp():
    body = "[core]\n\trepositoryformatversion = 0\n"
    found, _ = _probe({"/.git/config": _Resp(403, body)})
    assert "vcs-git" not in found


# --- toggle / integration ---------------------------------------------------
def test_dedupe_keeps_strongest_per_type():
    # both git checks fire; result has exactly one vcs-git finding
    found, _ = _probe({
        "/.git/config": _Resp(200, "[core]\nrepositoryformatversion = 0\n"),
        "/.git/HEAD": _Resp(200, "ref: refs/heads/main\n")})
    assert "vcs-git" in found
    # exactly one entry in the type map (dedupe collapsed the two checks)
    http = _FakeHTTP({
        "/.git/config": _Resp(200, "[core]\nrepositoryformatversion = 0\n"),
        "/.git/HEAD": _Resp(200, "ref: refs/heads/main\n")})
    out = _run(probes.probe_sensitive_paths(http, "http://t.local:8080/"))
    assert sum(1 for f in out if f["type"] == "vcs-git") == 1


def test_findings_sorted_severity_first():
    http = _FakeHTTP({
        "/metrics": _Resp(200, "# HELP go_goroutines x\ngo_goroutines 1\n"),
        "/.env": _Resp(200, "APP_KEY=secrettestvalue\n")})
    out = _run(probes.probe_sensitive_paths(http, "http://t.local:8080/"))
    sev = [f["severity"] for f in out]
    assert sev == sorted(sev, key=lambda s: {"high": 0, "medium": 1, "low": 2}[s])
    assert out[0]["severity"] == "high"
