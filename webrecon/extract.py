"""Endpoint, URL and parameter extraction from HTML and JavaScript.

The JS link-regex is inspired by LinkFinder's approach: capture quoted strings
that look like paths / endpoints / full URLs. We then classify and resolve them.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qsl

from . import utils


# ---------------------------------------------------------------------------
# Endpoint / URL regexes
# ---------------------------------------------------------------------------

# LinkFinder-style: content inside quotes that resembles a path or URL.
_LINKFINDER = re.compile(
    r"""
    (?:"|')                               # opening quote
    (
      (?:[a-zA-Z]{1,10}://|//)            # scheme or protocol-relative
      [^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,}   #   host + path
      |
      (?:/|\.\./|\./)                      # absolute or relative path
      [^"'><,;| *()%%$^/\\\[\]]            #   first char
      [^"'><,;|()]{1,}                     #   rest
      |
      [a-zA-Z0-9_\-/]{1,}/                 # bare path-ish
      [a-zA-Z0-9_\-/]{1,}
      \.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml|do|cgi)
      (?:\?[^"']{0,})?
      |
      [a-zA-Z0-9_\-/]{1,}                  # endpoint word with api-ish extension
      \.(?:json|action|php|asp|aspx|jsp)
      (?:\?[^"']{0,})?
    )
    (?:"|')                               # closing quote
    """,
    re.VERBOSE,
)

# Fully-qualified URLs anywhere in text
_FULL_URL = re.compile(r"""https?://[^\s"'<>()\]\[{}|\\^`]+""", re.I)

# fetch()/axios/XHR style API calls -> capture the URL argument
_API_CALL = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|\.open|\.ajax|url\s*[:=])\s*\(?\s*["'`]([^"'`]+)["'`]""",
    re.I,
)

# route / path string literals commonly used in SPAs
_ROUTE = re.compile(r"""["'`](/[a-zA-Z0-9_\-./:{}]+)["'`]""")


def extract_html_links(html: str) -> set[str]:
    """Pull raw link-ish strings from HTML attributes (href/src/action/data-*)."""
    out: set[str] = set()
    for m in re.finditer(
        r"""(?:href|src|action|data-url|data-src|data-href|formaction)\s*=\s*["']([^"']+)["']""",
        html, re.I,
    ):
        out.add(m.group(1))
    # srcset
    for m in re.finditer(r"""srcset\s*=\s*["']([^"']+)["']""", html, re.I):
        for part in m.group(1).split(","):
            cand = part.strip().split(" ")[0]
            if cand:
                out.add(cand)
    # meta refresh / og:url
    for m in re.finditer(r"""content\s*=\s*["'][^"']*url=([^"']+)["']""", html, re.I):
        out.add(m.group(1))
    return out


def extract_js_endpoints(js: str) -> set[str]:
    """Extract candidate endpoints/paths/URLs from a JS blob."""
    out: set[str] = set()
    for rx in (_LINKFINDER, _API_CALL, _ROUTE):
        for m in rx.finditer(js):
            val = m.group(1).strip()
            if _plausible(val):
                out.add(val)
    for m in _FULL_URL.finditer(js):
        out.add(m.group(0).rstrip(".,);"))
    return out


_JUNK_SUBSTR = ("text/", "application/", "image/", "@babel", "node_modules",
                "charset=", "+json", "octet-stream", ".min.map")


def _plausible(s: str) -> bool:
    if len(s) < 2 or len(s) > 400:
        return False
    if " " in s and not s.startswith(("http", "/")):
        return False
    low = s.lower()
    if any(j in low for j in _JUNK_SUBSTR):
        return False
    # pure version numbers / mime-ish
    if re.fullmatch(r"[0-9.]+", s):
        return False
    return True


def resolve_and_classify(base: str, raw: set[str]):
    """Resolve raw strings against base; split into (urls, params_map, unresolved).

    Returns:
      urls:        set of absolute http(s) URLs
      param_keys:  dict[endpoint_without_query] -> set(param names)
      unresolved:  set of strings we could not turn into absolute URLs (api words)
    """
    urls: set[str] = set()
    param_keys: dict[str, set[str]] = {}
    unresolved: set[str] = set()

    for item in raw:
        u = utils.normalize_url(base, item)
        if u:
            urls.add(u)
            clean, params = utils.split_params(u)
            if params:
                param_keys.setdefault(clean, set()).update(params.keys())
        else:
            # not resolvable but may still be a useful endpoint hint
            if re.search(r"[a-zA-Z0-9]/[a-zA-Z0-9]", item) or "?" in item:
                unresolved.add(item)
                # parse any params in the raw hint
                if "?" in item:
                    base_part, _, q = item.partition("?")
                    keys = {k for k, _ in parse_qsl(q, keep_blank_values=True)}
                    if keys:
                        param_keys.setdefault(base_part, set()).update(keys)
    return urls, param_keys, unresolved


def extract_all_params(urls: set[str]) -> dict[str, set[str]]:
    """Given a set of URLs, map each endpoint path -> set of observed param names."""
    out: dict[str, set[str]] = {}
    for u in urls:
        clean, params = utils.split_params(u)
        if params:
            out.setdefault(clean, set()).update(params.keys())
    return out
