"""Tests for the CORS reflection check.

A finding requires the server to echo back the exact Origin we sent; a static
ACAO, a bare ``*``, or no ACAO is never reported.
"""
import asyncio
from dataclasses import dataclass, field

from webrecon import cors


@dataclass
class _Resp:
    status: int = 200
    text: str = "ok"
    content_type: str = "text/plain"
    final_url: str = ""
    headers: dict = field(default_factory=dict)
    ok: bool = True
    error: str | None = None
    raw: bytes = b""


class _CorsHTTP:
    """policy(origin) -> (acao_or_None, acac_bool); builds the response headers."""
    def __init__(self, policy):
        self.policy = policy
        self.origins = []

    async def fetch(self, url, method="GET", headers=None, read_body=True,
                    data=None, json=None, auth=None):
        origin = (headers or {}).get("Origin", "")
        self.origins.append(origin)
        acao, acac = self.policy(origin)
        h = {}
        if acao is not None:
            h["access-control-allow-origin"] = acao
        if acac:
            h["access-control-allow-credentials"] = "true"
        return _Resp(headers=h, final_url=url)


def _run(policy):
    http = _CorsHTTP(policy)
    out = asyncio.run(cors.check_cors(http, "http://t.local:8080/"))
    return out, http


def test_reflect_any_origin_with_credentials_is_high():
    out, _ = _run(lambda o: (o, True))       # echoes whatever Origin, with creds
    assert len(out) == 1
    assert out[0]["severity"] == "high"
    assert out[0]["type"] == "cors-misconfig"
    assert "_creds" not in out[0]            # internal field stripped


def test_reflect_any_origin_without_credentials_is_medium():
    out, _ = _run(lambda o: (o, False))
    assert out[0]["severity"] == "medium"


def test_null_origin_trusted():
    out, _ = _run(lambda o: ((o, True) if o == "null" else (None, False)))
    assert out and "null" in out[0]["title"]
    assert out[0]["severity"] == "high"


def test_suffix_match_bypass():
    # server trusts any origin ending in its own host -> evil.t.local passes
    out, _ = _run(lambda o: ((o, True) if o.endswith("t.local") else (None, False)))
    assert out and out[0]["severity"] == "high"
    assert "t.local" in out[0]["evidence"]


def test_wildcard_is_not_reported():
    out, _ = _run(lambda o: ("*", True))     # '*' + creds is browser-invalid
    assert out == []


def test_static_acao_not_reflected_is_silent():
    out, _ = _run(lambda o: ("https://trusted.example", False))
    assert out == []


def test_no_cors_headers_is_silent():
    out, _ = _run(lambda o: (None, False))
    assert out == []


def test_credentialed_outranks_noncredentialed():
    # arbitrary reflects with creds (high), but suffix also reflects w/o creds;
    # the reported one must be the credentialed (high) result.
    def policy(o):
        if o == "null":
            return (None, False)
        if o.startswith("https://attacker-webrecon.example"):
            return (o, True)          # arbitrary origin, credentialed
        return (o, False)             # others reflect without creds
    out, _ = _run(policy)
    assert out[0]["severity"] == "high"
