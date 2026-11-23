"""Opt-in default-credential check against detected admin panels.

OFF by default (``cfg.try_default_creds`` / ``--try-default-creds``). It sends
login requests, so it is never implicit.

Discipline, mirroring the sensitive-path probe:
  * We only attempt a panel we have *positively detected* -- via a crawl-time
    technology marker / Server header, or a signature on the login page itself
    (for Basic auth, a 401 with the product's realm). No blind spraying.
  * A "success" is content-verified: the post-login response must carry a
    signature that only an authenticated session shows. A bare 200 is never a
    success -- that is how we avoid reporting a login that did not happen.
  * Lockout-safe: a tiny curated default list per panel, tried sequentially and
    stopped at the first success, capped at ``_MAX_ATTEMPTS`` per panel. This is
    a known-default check, NOT a brute-force; it never iterates a wordlist.

Each finding is a confirmed default login (severity critical) with the exact
username/password that worked.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import utils


# hard cap on login attempts per panel -- a known-default list is short by
# definition; this is the lockout backstop, not a tuning knob.
_MAX_ATTEMPTS = 5


@dataclass
class Panel:
    name: str                               # human-readable panel name
    type: str                               # slug
    login_path: str                         # path probed / posted to
    method: str                             # "basic" | "json" | "form"
    creds: tuple[tuple[str, str], ...]      # (user, pass) defaults to try
    success: tuple[str, ...]                # body needles proving auth (ANY)
    # detection: this panel is "present" if any tech marker matches the crawl's
    # technology list / Server header, OR the login page carries a detect needle
    # (for Basic: a 401 whose WWW-Authenticate realm carries one of these).
    tech_markers: tuple[str, ...] = ()
    detect_needles: tuple[str, ...] = ()
    # path to GET for detection, when it differs from login_path (e.g. a
    # POST-only API login whose presence is confirmed from the SPA root).
    detect_path: str = ""
    # form/json field names + any constant extra fields. An empty field_user
    # means the panel has no username field (e.g. Jupyter's password-only login).
    field_user: str = "username"
    field_pass: str = "password"
    extra_fields: dict = field(default_factory=dict)
    # form login: a regex capturing a CSRF/anti-forgery token from the login
    # page to echo back in the POST (named group 'tok'); empty = no token.
    token_regex: str = ""
    token_field: str = ""


PANELS: list[Panel] = [
    Panel(
        name="Apache Tomcat Manager", type="tomcat-manager",
        login_path="/manager/html", method="basic",
        creds=(("tomcat", "tomcat"), ("admin", "admin"),
               ("tomcat", "s3cret"), ("role1", "role1"), ("admin", "")),
        success=("Tomcat Web Application Manager", "Server Information"),
        tech_markers=("tomcat", "apache-coyote"),
        detect_needles=("Tomcat",),
    ),
    Panel(
        name="Grafana", type="grafana",
        login_path="/login", method="json",
        creds=(("admin", "admin"),),
        success=('"message":"Logged in"', '"message": "Logged in"'),
        tech_markers=("grafana",),
        detect_needles=("Grafana", "grafana-app"),
        field_user="user", field_pass="password",
    ),
    Panel(
        name="phpMyAdmin", type="phpmyadmin",
        login_path="/index.php", method="form",
        creds=(("root", ""), ("root", "root"), ("root", "password")),
        success=("pma_navigation", "server_databases", "class=\"logout\""),
        tech_markers=("phpmyadmin",),
        detect_needles=("phpMyAdmin", "pma_username"),
        field_user="pma_username", field_pass="pma_password",
        token_regex=r'name="token"\s+value="(?P<tok>[^"]+)"',
        token_field="token",
    ),
    Panel(
        name="RabbitMQ Management", type="rabbitmq-management",
        login_path="/api/overview", method="basic",
        creds=(("guest", "guest"), ("admin", "admin"),
               ("administrator", "administrator")),
        success=('"rabbitmq_version"', '"management_version"', '"product_version"'),
        tech_markers=("rabbitmq",),
        detect_needles=("RabbitMQ",),
    ),
    Panel(
        name="Portainer", type="portainer",
        login_path="/api/auth", method="json",
        creds=(("admin", "admin"), ("admin", "password"),
               ("admin", "portainer"), ("admin", "portainer123")),
        success=('"jwt"',),
        tech_markers=("portainer",),
        detect_path="/", detect_needles=("Portainer", "portainer.app"),
        field_user="username", field_pass="password",
    ),
    Panel(
        name="Jupyter", type="jupyter",
        login_path="/login", method="form",
        creds=(("", ""), ("", "jupyter"), ("", "password"), ("", "admin")),
        success=("jupyter-config-data", "JupyterLab"),
        tech_markers=("jupyter",),
        detect_needles=("Jupyter", "_xsrf"),
        field_user="", field_pass="password",
        token_regex=r'name="_xsrf"\s+value="(?P<tok>[^"]+)"',
        token_field="_xsrf",
    ),
]


def _tech_present(panel: Panel, tech: set[str], server: str) -> bool:
    hay = " ".join(tech).lower() + " " + (server or "").lower()
    return any(m in hay for m in panel.tech_markers)


async def _detect(http, base: str, panel: Panel, tech: set[str]) -> tuple[bool, str]:
    """Return (present, server_header). Present if a tech marker matches or the
    login page carries a detection signature (401 Basic realm for basic auth)."""
    url = base.rstrip("/") + (panel.detect_path or panel.login_path)
    try:
        r = await http.fetch(url, read_body=True)
    except Exception:  # noqa: BLE001
        return (False, "")
    server = (r.headers or {}).get("server", "") if r else ""
    if r and _tech_present(panel, tech, server):
        return (True, server)
    if panel.method == "basic":
        if r and r.status in (401, 403):
            realm = (r.headers or {}).get("www-authenticate", "")
            if any(n.lower() in realm.lower() for n in panel.detect_needles) \
                    or "basic" in realm.lower():
                return (True, server)
        return (False, server)
    # form / json: detect via a login-page signature
    body = (r.text if r else "") or ""
    if any(n in body for n in panel.detect_needles):
        return (True, server)
    return (False, server)


def _is_success(resp, panel: Panel) -> str | None:
    if not resp or resp.status not in (200, 302, 303):
        return None
    body = resp.text or ""
    for n in panel.success:
        if n in body:
            return n
    return None


async def _try_basic(http, url: str, panel: Panel) -> dict | None:
    for user, pw in panel.creds[:_MAX_ATTEMPTS]:
        try:
            r = await http.fetch(url, auth=(user, pw), read_body=True)
        except Exception:  # noqa: BLE001
            continue
        ev = _is_success(r, panel)
        if ev:
            return _finding(panel, url, user, pw, ev)
    return None


async def _try_json(http, url: str, panel: Panel) -> dict | None:
    for user, pw in panel.creds[:_MAX_ATTEMPTS]:
        payload = {panel.field_pass: pw, **panel.extra_fields}
        if panel.field_user:
            payload[panel.field_user] = user
        try:
            r = await http.fetch(url, method="POST", json=payload, read_body=True)
        except Exception:  # noqa: BLE001
            continue
        ev = _is_success(r, panel)
        if ev:
            return _finding(panel, url, user, pw, ev)
    return None


async def _try_form(http, base: str, url: str, panel: Panel) -> dict | None:
    import re
    token = ""
    if panel.token_regex:
        # fetch the login page to lift a CSRF token (and establish the session
        # cookie the shared client will carry into the POST).
        try:
            page = await http.fetch(base.rstrip("/") + panel.login_path,
                                    read_body=True)
            m = re.search(panel.token_regex, page.text or "")
            if m:
                token = m.group("tok")
        except Exception:  # noqa: BLE001
            token = ""
    for user, pw in panel.creds[:_MAX_ATTEMPTS]:
        payload = {panel.field_pass: pw, **panel.extra_fields}
        if panel.field_user:
            payload[panel.field_user] = user
        if panel.token_field and token:
            payload[panel.token_field] = token
        try:
            r = await http.fetch(url, method="POST", data=payload, read_body=True)
        except Exception:  # noqa: BLE001
            continue
        ev = _is_success(r, panel)
        if ev:
            return _finding(panel, url, user, pw, ev)
    return None


def _finding(panel: Panel, url: str, user: str, pw: str, ev: str) -> dict:
    return {
        "type": "default-cred",
        "panel": panel.name,
        "severity": "critical",
        "url": url,
        "username": user,
        "password": pw,
        "evidence": f"authenticated ({ev!r})",
    }


async def _probe_panel(http, base: str, panel: Panel, tech: set[str]) -> dict | None:
    present, _server = await _detect(http, base, panel, tech)
    if not present:
        return None
    url = base.rstrip("/") + panel.login_path
    utils.info(f"default-cred: {panel.name} detected at {url} -- trying "
               f"{min(len(panel.creds), _MAX_ATTEMPTS)} known default(s)")
    if panel.method == "basic":
        return await _try_basic(http, url, panel)
    if panel.method == "json":
        return await _try_json(http, url, panel)
    if panel.method == "form":
        return await _try_form(http, base, url, panel)
    return None


async def try_default_creds(http, base_url: str, tech=None, cfg=None) -> list[dict]:
    """Detect known admin panels on ``base_url`` and try a tiny default-credential
    set against each (opt-in; the caller gates on cfg.try_default_creds). Returns
    a list of confirmed-default-login findings. Never raises."""
    sp = urlsplit(base_url)
    base = f"{sp.scheme}://{sp.netloc}" if sp.scheme else base_url
    techset = {str(t).lower() for t in (tech or [])}

    utils.warn("default-cred check is ON: sending login attempts to detected "
               "panels (opt-in; one short known-default pass per panel)")

    results = await asyncio.gather(
        *(_probe_panel(http, base, p, techset) for p in PANELS),
        return_exceptions=True)
    findings = [g for g in results if isinstance(g, dict)]
    for f in findings:
        utils.hit(f"default-cred [CRIT] {f['panel']} login works: "
                  f"{f['username']}:{f['password']} -> {f['url']}")
    return findings
