"""Tests for the opt-in default-credential check.

A "success" must be content-verified (a post-login signature), a panel is only
attempted when positively detected, and wrong creds yield nothing. All the
credential pairs here are the PUBLIC vendor defaults used as test fixtures.
"""
import asyncio
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from webrecon import defaultcreds


@dataclass
class _Resp:
    status: int
    text: str = ""
    content_type: str = "text/html"
    final_url: str = ""
    headers: dict = field(default_factory=dict)
    ok: bool = True
    error: str | None = None
    raw: bytes = b""


class _FakeHTTP:
    """Routes each request through a handler(method, path, auth, data, json)."""
    def __init__(self, handler):
        self.handler = handler
        self.requested = []

    async def fetch(self, url, method="GET", headers=None, read_body=True,
                    data=None, json=None, auth=None):
        path = urlsplit(url).path
        self.requested.append((method, path, auth, data, json))
        r = self.handler(method, path, auth, data, json)
        if r is None:
            return _Resp(404, "not found", final_url=url)
        r.final_url = url
        return r


def _run(coro, tech=None):
    http = _FakeHTTP(coro)
    out = asyncio.run(defaultcreds.try_default_creds(
        http, "http://t.local:8080/", tech=tech or []))
    return {f["panel"]: f for f in out}, http


# --- Tomcat (HTTP Basic) ----------------------------------------------------
def _tomcat_handler(valid=("tomcat", "tomcat")):
    def h(method, path, auth, data, json):
        if path != "/manager/html":
            return None
        if auth is None:
            return _Resp(401, "", headers={
                "www-authenticate": 'Basic realm="Tomcat Manager Application"'})
        if tuple(auth) == valid:
            return _Resp(200, "<html><title>...</title>"
                              "Tomcat Web Application Manager</html>")
        return _Resp(401, "", headers={"www-authenticate": "Basic"})
    return h


def test_tomcat_default_login_confirmed():
    found, http = _run(_tomcat_handler(("tomcat", "tomcat")))
    assert "Apache Tomcat Manager" in found
    f = found["Apache Tomcat Manager"]
    assert f["severity"] == "critical"
    assert (f["username"], f["password"]) == ("tomcat", "tomcat")


def test_tomcat_detected_via_401_realm_then_admin_admin():
    found, _ = _run(_tomcat_handler(("admin", "admin")))
    assert found["Apache Tomcat Manager"]["username"] == "admin"


def test_tomcat_wrong_creds_no_finding():
    found, http = _run(_tomcat_handler(("x", "y")))   # no default matches
    assert "Apache Tomcat Manager" not in found
    # it was detected (401 realm) and did attempt the defaults
    assert any(m == "GET" and p == "/manager/html" and a is not None
               for (m, p, a, _d, _j) in http.requested)


def test_tomcat_200_without_signature_is_not_success():
    def h(method, path, auth, data, json):
        if path != "/manager/html":
            return None
        if auth is None:
            return _Resp(401, "", headers={"www-authenticate": 'Basic realm="Tomcat"'})
        return _Resp(200, "<html>welcome, nothing sensitive here</html>")
    found, _ = _run(h)
    assert found == {}


# --- Grafana (JSON login) ---------------------------------------------------
def test_grafana_default_login_confirmed_via_tech_marker():
    def h(method, path, auth, data, json):
        if path == "/login" and method == "GET":
            return _Resp(200, "<html>Grafana</html>")
        if path == "/login" and method == "POST":
            if json and json.get("user") == "admin" and json.get("password") == "admin":
                return _Resp(200, '{"message":"Logged in"}',
                             content_type="application/json")
            return _Resp(401, '{"message":"invalid username or password"}')
        return None
    found, _ = _run(h, tech=["Grafana"])
    assert found["Grafana"]["severity"] == "critical"
    assert found["Grafana"]["username"] == "admin"


def test_grafana_wrong_password_no_finding():
    def h(method, path, auth, data, json):
        if path == "/login" and method == "GET":
            return _Resp(200, "<html>Grafana login</html>")
        if path == "/login" and method == "POST":
            return _Resp(401, '{"message":"invalid username or password"}')
        return None
    found, _ = _run(h, tech=["Grafana"])
    assert "Grafana" not in found


# --- phpMyAdmin (form + CSRF token + session cookie) ------------------------
def test_phpmyadmin_default_login_with_token():
    def h(method, path, auth, data, json):
        if path == "/index.php" and method == "GET":
            return _Resp(200, '<html>phpMyAdmin <input name="token" '
                              'value="abc123"></html>')
        if path == "/index.php" and method == "POST":
            if data and data.get("pma_username") == "root" \
                    and data.get("pma_password") == "" \
                    and data.get("token") == "abc123":
                return _Resp(200, '<html><div id="pma_navigation">db</div></html>')
            return _Resp(200, "<html>Cannot log in to the MySQL server</html>")
        return None
    found, _ = _run(h)
    assert found["phpMyAdmin"]["severity"] == "critical"
    assert (found["phpMyAdmin"]["username"],
            found["phpMyAdmin"]["password"]) == ("root", "")


# --- detection gate ---------------------------------------------------------
def test_absent_panels_are_not_attempted():
    """Everything 404s and no tech markers -> no detection, no login requests."""
    def h(method, path, auth, data, json):
        return None
    found, http = _run(h)
    assert found == {}
    # a 404 detection GET is fine, but no authenticated / POST attempt is made
    assert all(a is None and d is None and j is None
               for (_m, _p, a, d, j) in http.requested)


def test_grafana_not_detected_without_marker_or_signature():
    def h(method, path, auth, data, json):
        if path == "/login":
            return _Resp(200, "<html>some unrelated login page</html>")
        return None
    found, http = _run(h)                 # no tech marker, no "Grafana" in body
    assert "Grafana" not in found
    # detection GET happened, but no POST login attempt
    assert not any(m == "POST" for (m, _p, _a, _d, _j) in http.requested)
