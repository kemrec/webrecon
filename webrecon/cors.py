"""CORS reflection / misconfiguration check.

Header-verified, so false positives are rare: we send a crafted ``Origin`` and
only report when the server *reflects that exact origin* back in
``Access-Control-Allow-Origin`` (ACAO). A static ACAO, an absent one, or a
plain ``*`` is not reported -- ``*`` cannot be combined with credentials by any
browser, so it is not an exploitable finding on its own.

Origins probed (each catches a different broken check):
  * an arbitrary attacker origin         -> full reflection ("echo the Origin")
  * ``null``                             -> `Origin: null` trusted (sandboxed
                                            iframes, data: URLs, redirects)
  * ``https://evil.<host>``              -> naive suffix match (`endswith(host)`)
  * ``https://<host>.attacker.example``  -> naive substring match (`host in origin`)

When the reflected origin is paired with ``Access-Control-Allow-Credentials:
true`` the impact is a credentialed cross-origin read (high); without
credentials it is a cross-origin read of the (unauthenticated) response
(medium). Only the single most severe result is reported.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from . import utils


_ATTACKER = "attacker-webrecon.example"


def _origins(host: str) -> list[tuple[str, str]]:
    """(label, origin) pairs to probe for the given target host."""
    out = [
        ("arbitrary origin reflected", f"https://{_ATTACKER}"),
        ("null origin trusted", "null"),
    ]
    if host:
        out.append(("suffix-match bypass", f"https://evil.{host}"))
        out.append(("substring-match bypass", f"https://{host}.{_ATTACKER}"))
    return out


def _hdr(resp, name: str) -> str:
    return ((resp.headers or {}).get(name, "") if resp else "").strip()


async def _probe(http, url: str, label: str, origin: str) -> dict | None:
    try:
        r = await http.fetch(url, headers={"Origin": origin})
    except Exception:  # noqa: BLE001
        return None
    if not r or not r.ok:
        return None
    acao = _hdr(r, "access-control-allow-origin")
    if not acao or acao == "*":
        return None
    # the signature: the server echoed back the exact origin we sent.
    if acao != origin:
        return None
    creds = _hdr(r, "access-control-allow-credentials").lower() == "true"
    sev = "high" if creds else "medium"
    return {
        "type": "cors-misconfig",
        "title": f"CORS misconfiguration ({label}"
                 f"{', with credentials' if creds else ''})",
        "severity": sev,
        "path": urlsplit(url).path or "/",
        "url": url,
        "evidence": f"Origin: {origin} -> ACAO: {acao}, "
                    f"ACAC: {'true' if creds else 'false'}",
        "_creds": creds,
    }


_SEV = {"high": 0, "medium": 1, "low": 2}


async def check_cors(http, base_url: str, cfg=None) -> list[dict]:
    """Probe the base URL for CORS origin-reflection. Returns 0 or 1 finding
    (the most severe). Never raises."""
    sp = urlsplit(base_url)
    base = f"{sp.scheme}://{sp.netloc}" if sp.scheme else base_url
    host = (sp.hostname or "").lower()
    url = base.rstrip("/") + "/"

    results = await asyncio.gather(
        *(_probe(http, url, lbl, org) for lbl, org in _origins(host)),
        return_exceptions=True)
    hits = [g for g in results if isinstance(g, dict)]
    if not hits:
        return []
    # worst severity first, credentialed outranking non-credentialed
    hits.sort(key=lambda d: (_SEV[d["severity"]], not d["_creds"]))
    best = hits[0]
    best.pop("_creds", None)
    utils.hit(f"exposure [{best['severity'][:1].upper()}] {best['title']} "
              f"-> {best['url']}")
    return [best]
