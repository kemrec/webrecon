"""Content-verified sensitive-path probe.

A small, high-signal checklist run against each web port after the crawl. Each
check fetches one conventional path and only reports a finding when the
response *body* carries an expected signature -- never on a bare 200. This
content gate is the whole point: catch-all SPAs, soft-404s and auth walls serve
200s for almost any path, so a status-only probe is nothing but false
positives. We match a signature or we stay silent.

Covers (highest-impact first):
  * VCS / source exposure: .git, .svn, .hg
  * Spring Boot Actuator: /actuator, /actuator/env, /actuator/mappings,
    and heapdump (confirmed via the actuator link index, never downloaded)
  * secrets-in-files: .env, .htpasswd, web.config, .DS_Store
  * status / debug surfaces: Apache server-status, Go pprof, Prometheus metrics
  * unauthenticated datastore HTTP: Elasticsearch, CouchDB, Kibana
  * directory listing / autoindex

Only read-only GETs of conventional paths are made.
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import utils


# --- signature primitives ---------------------------------------------------

# A body that is plainly an HTML document. Most "found everything" false
# positives are an app shell / soft-404 served with status 200; any non-HTML
# check (a VCS file, a JSON API, a .env) rejects such a body outright.
_HTML_RE = re.compile(rb"<!doctype html|<html[\s>]", re.I)


def _looks_html(resp) -> bool:
    head = resp.raw[:512] or (resp.text[:512].encode("utf-8", "replace"))
    return bool(_HTML_RE.search(head))


@dataclass
class Check:
    """One content-verified probe. A finding is emitted only when the fetched
    body matches the signature (any of ``needles`` / all of ``all_needles`` /
    ``regex``)."""
    type: str                       # category slug (also the dedupe key)
    title: str                      # human-readable description
    path: str                       # path appended to the base URL
    severity: str                   # high | medium | low
    needles: tuple[str, ...] = ()           # ANY of these present in the body
    all_needles: tuple[str, ...] = ()       # ALL of these present in the body
    regex: str = ""                         # OR this pattern matches the body
    binary: tuple[bytes, ...] = ()          # ANY of these byte magics in raw head
    html_ok: bool = False           # this check's own signature IS html
    _rx: re.Pattern | None = field(default=None, repr=False, compare=False)

    def compiled(self) -> re.Pattern | None:
        if self.regex and self._rx is None:
            self._rx = re.compile(self.regex, re.I | re.M)
        return self._rx


def _window(text: str, idx: int, span: int = 140) -> str:
    """A compact single-line evidence snippet around a match offset."""
    start = max(0, idx - 20)
    frag = text[start:start + span]
    frag = re.sub(r"\s+", " ", frag).strip()
    return frag[:span]


def _match(resp, chk: Check) -> str | None:
    """Return an evidence snippet if the response satisfies the signature, else
    None. Only status-200 bodies are considered, and non-HTML checks reject an
    HTML body (the soft-404 / SPA false-positive guard)."""
    if not resp or resp.status != 200:
        return None

    # binary-magic checks look at the raw head, not the decoded text.
    if chk.binary:
        for magic in chk.binary:
            i = resp.raw.find(magic)
            if i != -1:
                return f"magic {magic!r} @ offset {i}"
        return None

    body = resp.text or ""
    if not body:
        return None
    if not chk.html_ok and _looks_html(resp):
        return None

    if chk.all_needles:
        first = None
        for n in chk.all_needles:
            i = body.find(n)
            if i == -1:
                return None
            first = i if first is None else min(first, i)
        return _window(body, first)

    if chk.needles:
        for n in chk.needles:
            i = body.find(n)
            if i != -1:
                return _window(body, i)
        # fall through to regex if also set

    rx = chk.compiled()
    if rx:
        m = rx.search(body)
        if m:
            return _window(body, m.start())

    return None


# --- the checklist -----------------------------------------------------------
# Ordered highest-impact first. Several checks may share a ``type`` (e.g. two
# ways to confirm .git); findings are deduped by type, strongest kept.

CHECKS: list[Check] = [
    # ---- VCS / source exposure ----
    Check("vcs-git", "Exposed .git/ repository (source/history disclosure)",
          "/.git/config", "high",
          all_needles=("[core]", "repositoryformatversion")),
    Check("vcs-git", "Exposed .git/ repository (source/history disclosure)",
          "/.git/HEAD", "high", regex=r"^ref:\s+refs/"),
    Check("vcs-svn", "Exposed .svn/ working copy (source disclosure)",
          "/.svn/entries", "medium", regex=r"(?s)\A\s*\d+\s.*\bdir\b"),
    Check("vcs-hg", "Exposed .hg/ repository (source disclosure)",
          "/.hg/requires", "medium",
          needles=("revlogv1", "dotencode", "fncache", "generaldelta", "store")),

    # ---- Spring Boot Actuator (handled partly in code for heapdump) ----
    Check("actuator", "Spring Boot Actuator exposed (endpoint index)",
          "/actuator", "medium", needles=('"_links"',)),
    Check("actuator-env", "Spring Boot Actuator /env exposed (config + secrets)",
          "/actuator/env", "high", needles=('"activeProfiles"', '"propertySources"')),
    Check("actuator-mappings", "Spring Boot Actuator /mappings exposed (route map)",
          "/actuator/mappings", "medium", needles=('"dispatcherServlets"', '"contexts"')),

    # ---- secrets in files ----
    Check("dotenv", "Exposed .env file (application secrets)",
          "/.env", "high",
          regex=r"(?m)^\s*(APP_KEY|APP_ENV|DB_|DATABASE_URL|SECRET_KEY|"
                r"AWS_ACCESS_KEY|AWS_SECRET|REDIS_|MAIL_|JWT_SECRET)\w*\s*="),
    Check("htpasswd", "Exposed .htpasswd (password hashes)",
          "/.htpasswd", "high",
          regex=r":(\$(2[aby]|apr1|1|5|6)\$|\{SHA\}|\{SSHA\})"),
    Check("iis-webconfig", "Exposed web.config (IIS config, possible secrets)",
          "/web.config", "high", all_needles=("<configuration", "<system.web")),
    Check("ds-store", "Exposed .DS_Store (directory name disclosure)",
          "/.DS_Store", "low", binary=(b"Bud1",)),

    # ---- status / debug surfaces ----
    Check("apache-status", "Apache mod_status /server-status exposed",
          "/server-status", "medium", html_ok=True,
          needles=("Apache Server Status",)),
    Check("go-pprof", "Go net/http/pprof debug surface exposed",
          "/debug/pprof/", "medium", html_ok=True,
          all_needles=("Types of profiles available", "goroutine")),
    Check("prometheus", "Prometheus metrics endpoint exposed",
          "/metrics", "low", regex=r"(?m)^#\s(HELP|TYPE)\s|\bgo_goroutines\b"),

    # ---- unauthenticated datastore HTTP ----
    Check("elasticsearch", "Unauthenticated Elasticsearch HTTP API",
          "/_cluster/health", "high",
          all_needles=('"cluster_name"', '"number_of_nodes"')),
    Check("couchdb", "Unauthenticated CouchDB HTTP API (database list)",
          "/_all_dbs", "high", regex=r'\[\s*("?_(users|replicator|global_changes)")'),
    Check("kibana", "Kibana status endpoint exposed",
          "/api/status", "medium", all_needles=('"status"', '"version"', '"number"')),
]

# directory listing / autoindex -- applied to a short list of common dirs so we
# catch an autoindexed root or an exposed uploads/backup folder.
_AUTOINDEX_DIRS = ("/", "/uploads/", "/files/", "/backup/", "/backups/",
                   "/assets/", "/images/", "/static/", "/data/")
_AUTOINDEX_RE = re.compile(
    r"<title>\s*Index of /|Directory listing for /|"
    r"<h1>\s*Index of /", re.I)
_AUTOINDEX_PARENT = ("Parent Directory", "../")


def _finding(chk: Check, base: str, evidence: str) -> dict:
    return {
        "type": chk.type,
        "title": chk.title,
        "severity": chk.severity,
        "path": chk.path,
        "url": base.rstrip("/") + chk.path,
        "evidence": evidence,
    }


async def _run_check(http, base: str, chk: Check) -> dict | None:
    url = base.rstrip("/") + chk.path
    try:
        r = await http.fetch(url)
    except Exception:  # noqa: BLE001
        return None
    ev = _match(r, chk)
    if ev is None:
        return None
    return _finding(chk, base, ev)


async def _probe_heapdump_link(http, base: str) -> dict | None:
    """Confirm an exposed Actuator heapdump via the actuator link index WITHOUT
    downloading it (a heapdump can be gigabytes). We only report it when the
    actuator index actually advertises a heapdump endpoint."""
    url = base.rstrip("/") + "/actuator"
    try:
        r = await http.fetch(url)
    except Exception:  # noqa: BLE001
        return None
    if not r or r.status != 200 or not r.text:
        return None
    try:
        doc = json.loads(r.text)
    except ValueError:
        return None
    links = doc.get("_links") if isinstance(doc, dict) else None
    if not isinstance(links, dict) or "heapdump" not in links:
        return None
    href = ""
    hd = links.get("heapdump")
    if isinstance(hd, dict):
        href = str(hd.get("href", ""))
    path = urlsplit(href).path or "/actuator/heapdump"
    return {
        "type": "actuator-heapdump",
        "title": "Spring Boot Actuator heapdump exposed (full memory dump)",
        "severity": "high",
        "path": path,
        "url": href or (base.rstrip("/") + "/actuator/heapdump"),
        "evidence": "advertised in /actuator _links",
    }


async def _probe_autoindex(http, base: str) -> list[dict]:
    async def one(d: str) -> dict | None:
        url = base.rstrip("/") + d
        try:
            r = await http.fetch(url)
        except Exception:  # noqa: BLE001
            return None
        if not r or r.status != 200 or not r.text:
            return None
        body = r.text
        if not _AUTOINDEX_RE.search(body):
            return None
        # require a parent-dir / entry link so a page that merely says
        # "index of" in prose isn't mistaken for an autoindex.
        if not any(p in body for p in _AUTOINDEX_PARENT):
            return None
        m = _AUTOINDEX_RE.search(body)
        return {
            "type": "dir-listing",
            "title": "Directory listing / autoindex enabled",
            "severity": "medium",
            "path": d,
            "url": url,
            "evidence": _window(body, m.start()),
        }

    results = await asyncio.gather(*(one(d) for d in _AUTOINDEX_DIRS))
    out, seen = [], set()
    for f in results:
        if f and f["path"] not in seen:
            seen.add(f["path"])
            out.append(f)
    return out


_SEV_RANK = {"high": 0, "medium": 1, "low": 2}


async def probe_sensitive_paths(http, base_url: str, cfg=None) -> list[dict]:
    """Run the content-verified checklist against ``base_url`` (scheme://host[:port]).
    Returns a list of finding dicts, deduped by type (strongest kept), ordered
    severity-first. Never raises -- a probe failure yields no finding."""
    sp = urlsplit(base_url)
    base = f"{sp.scheme}://{sp.netloc}" if sp.scheme else base_url

    tasks = [_run_check(http, base, c) for c in CHECKS]
    tasks.append(_probe_heapdump_link(http, base))
    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[dict] = []
    for g in gathered:
        if isinstance(g, dict):
            findings.append(g)
        # BaseException from a task is swallowed: a probe must never abort the set
    findings.extend(await _probe_autoindex(http, base))

    # dedupe by type: keep the highest-severity hit per type (first on ties)
    best: dict[str, dict] = {}
    for f in findings:
        cur = best.get(f["type"])
        if cur is None or _SEV_RANK[f["severity"]] < _SEV_RANK[cur["severity"]]:
            best[f["type"]] = f

    out = sorted(best.values(),
                 key=lambda d: (_SEV_RANK[d["severity"]], d["type"]))
    for f in out:
        utils.hit(f"exposure [{f['severity'][:1].upper()}] {f['title']} "
                  f"-> {f['url']}")
    return out
