"""Lightweight technology fingerprinting (Wappalyzer-style, no dependency).

Given response headers and HTML, match a compact signature table over:
  - response headers (Server, X-Powered-By, X-Generator, etc.)
  - Set-Cookie names (session cookie conventions)
  - <meta name=generator>
  - body markers and script/src paths

Returns a set of "Name" or "Name x.y" labels. Deliberately conservative and
cheap — it runs on every crawled page.
"""
from __future__ import annotations

import re

# (compiled regex, label, group-index-for-version-or-None)
_HEADER_SIGS = [
    (re.compile(r"\bnginx/?([0-9.]+)?", re.I), "nginx", 1),
    (re.compile(r"\bApache/?([0-9.]+)?", re.I), "Apache", 1),
    (re.compile(r"\bcloudflare\b", re.I), "Cloudflare", None),
    (re.compile(r"\bMicrosoft-IIS/?([0-9.]+)?", re.I), "IIS", 1),
    (re.compile(r"\bgunicorn/?([0-9.]+)?", re.I), "gunicorn", 1),
    (re.compile(r"\bExpress\b", re.I), "Express", None),
    (re.compile(r"\bPHP/?([0-9.]+)?", re.I), "PHP", 1),
    (re.compile(r"\bASP\.NET\b", re.I), "ASP.NET", None),
    (re.compile(r"\bPleskLin\b|\bcPanel\b", re.I), "cPanel/Plesk", None),
]
_BODY_SIGS = [
    (re.compile(r"/wp-(content|includes)/", re.I), "WordPress", None),
    (re.compile(r'name="generator"[^>]*content="WordPress ?([0-9.]+)?', re.I), "WordPress", 1),
    (re.compile(r"/sites/(default|all)/|Drupal\.settings", re.I), "Drupal", None),
    (re.compile(r"/media/jui/|Joomla!", re.I), "Joomla", None),
    (re.compile(r"\bcsrf-token\b|rails-ujs|/assets/application-[0-9a-f]{8,}", re.I), "Ruby on Rails", None),
    (re.compile(r"__NEXT_DATA__|/_next/static/", re.I), "Next.js", None),
    (re.compile(r"\bdata-reactroot\b|react(?:-dom)?(?:\.production)?\.min\.js", re.I), "React", None),
    (re.compile(r"ng-version=\"([0-9.]+)\"|/@angular/", re.I), "Angular", 1),
    (re.compile(r"\bVue\b\.(?:runtime\.)?(?:global|esm)|data-v-[0-9a-f]{8}", re.I), "Vue.js", None),
    (re.compile(r"jquery[.-]([0-9.]+)?(?:\.min)?\.js", re.I), "jQuery", 1),
    (re.compile(r"bootstrap[.-]([0-9.]+)?(?:\.min)?\.(?:css|js)", re.I), "Bootstrap", 1),
    (re.compile(r"/static/admin/|csrfmiddlewaretoken", re.I), "Django", None),
    (re.compile(r"Laravel|laravel_session", re.I), "Laravel", None),
    (re.compile(r"X-Grafana|grafana-app", re.I), "Grafana", None),
]
_COOKIE_SIGS = [
    (re.compile(r"\bPHPSESSID\b"), "PHP", None),
    (re.compile(r"\bJSESSIONID\b"), "Java (servlet)", None),
    (re.compile(r"\bASP\.NET_SessionId\b|\b\.AspNetCore"), "ASP.NET", None),
    (re.compile(r"\blaravel_session\b"), "Laravel", None),
    (re.compile(r"\bwordpress_logged_in"), "WordPress", None),
    (re.compile(r"\bcsrftoken\b|\bdjango"), "Django", None),
    (re.compile(r"\bconnect\.sid\b"), "Express", None),
]


def _apply(sigs, text, out):
    for rx, label, gi in sigs:
        m = rx.search(text)
        if not m:
            continue
        ver = ""
        if gi and m.lastindex and m.lastindex >= gi:
            ver = (m.group(gi) or "")
        out.add(f"{label} {ver}".strip())


def detect(headers: dict | None, html: str | None) -> set[str]:
    out: set[str] = set()
    headers = headers or {}
    # normalize header values into one searchable blob (+ dedicated cookie scan)
    hblob = " ".join(f"{k}: {v}" for k, v in headers.items())
    _apply(_HEADER_SIGS, hblob, out)
    # cookies
    cookie = ""
    for k, v in headers.items():
        if k.lower() in ("set-cookie", "cookie"):
            cookie += " " + str(v)
    if cookie:
        _apply(_COOKIE_SIGS, cookie, out)
    # explicit powered-by / generator headers as labels
    for hk in ("x-powered-by", "x-generator", "x-aspnet-version"):
        val = headers.get(hk) or headers.get(hk.title()) or ""
        if val:
            out.add(str(val).split(",")[0].strip()[:40])
    if html:
        _apply(_BODY_SIGS, html, out)
    return {o for o in out if o}
