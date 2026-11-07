"""Async HTTP client wrapper over httpx with concurrency control & retries."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

from .config import Config
from . import utils


class _MappedTransport(httpx.AsyncHTTPTransport):
    """Transport that redirects requests for mapped hostnames to a fixed IP.

    The TCP connection goes to the mapped IP, but the original hostname is kept
    for both the ``Host`` header (already set by the client before the request
    reaches us) and the TLS SNI (via the ``sni_hostname`` extension). This lets
    us enumerate virtual hosts / cert-only names against a known IP without
    editing /etc/hosts. TLS verification is expected to be off for recon.
    """

    def __init__(self, resolve_map: dict, **kwargs):
        super().__init__(**kwargs)
        self._map = {h.lower(): ip for h, ip in resolve_map.items()}

    async def handle_async_request(self, request):
        host = (request.url.host or "").lower()
        ip = self._map.get(host)
        if ip:
            ext = dict(request.extensions)
            ext.setdefault("sni_hostname", host)
            request.extensions = ext
            request.url = request.url.copy_with(host=ip)
        return await super().handle_async_request(request)


@dataclass
class Response:
    url: str
    status: int
    final_url: str
    headers: dict
    text: str
    content_type: str
    length: int
    ok: bool
    error: str | None = None


class HTTPClient:
    """Thin async client. One instance per run; shares a semaphore for concurrency."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._sem = asyncio.Semaphore(cfg.concurrency)
        headers = {"User-Agent": cfg.user_agent, **cfg.extra_headers}
        limits = httpx.Limits(max_connections=cfg.concurrency * 2,
                              max_keepalive_connections=cfg.concurrency)
        resolve_map = getattr(cfg, "resolve_map", None)
        if resolve_map:
            # custom transport handles the hostname->IP mapping; verify/proxy
            # must be set on the transport rather than the client.
            transport = _MappedTransport(resolve_map, verify=cfg.verify_tls,
                                         proxy=cfg.proxy, limits=limits,
                                         retries=cfg.retries)
            self._client = httpx.AsyncClient(
                headers=headers, timeout=cfg.timeout,
                follow_redirects=True, transport=transport,
            )
        else:
            self._client = httpx.AsyncClient(
                headers=headers, timeout=cfg.timeout, verify=cfg.verify_tls,
                follow_redirects=True, proxy=cfg.proxy, limits=limits,
            )

    async def close(self) -> None:
        await self._client.aclose()

    async def fetch(self, url: str, method: str = "GET",
                    headers: dict | None = None,
                    read_body: bool = True) -> Response:
        """Fetch a URL with retries; never raises — returns Response with error set."""
        last_err = "unknown"
        for attempt in range(self.cfg.retries + 1):
            async with self._sem:
                try:
                    r = await self._client.request(method, url, headers=headers)
                    body = ""
                    if read_body:
                        ctype = r.headers.get("content-type", "")
                        # read text for textual content; skip huge binaries
                        if any(t in ctype for t in ("text", "javascript", "json",
                                                    "xml", "html", "")) or not ctype:
                            body = r.text
                    return Response(
                        url=url,
                        status=r.status_code,
                        final_url=str(r.url),
                        headers=dict(r.headers),
                        text=body,
                        content_type=r.headers.get("content-type", ""),
                        length=int(r.headers.get("content-length", len(r.content or b""))),
                        ok=True,
                    )
                except Exception as e:  # noqa: BLE001
                    last_err = f"{type(e).__name__}: {e}"
                    if attempt < self.cfg.retries:
                        await asyncio.sleep(0.4 * (attempt + 1))
        utils.debug(f"fetch failed {url}: {last_err}")
        return Response(url=url, status=0, final_url=url, headers={}, text="",
                        content_type="", length=0, ok=False, error=last_err)

    async def head_or_get(self, url: str, host_header: str | None = None) -> Response:
        """Liveness probe: try HEAD, fall back to GET if server rejects HEAD."""
        extra = {"Host": host_header} if host_header else None
        r = await self.fetch(url, method="HEAD", headers=extra, read_body=False)
        if (not r.ok) or r.status in (405, 501):
            r = await self.fetch(url, method="GET", headers=extra, read_body=False)
        return r
