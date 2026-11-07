"""Async HTTP client wrapper over httpx with concurrency control & retries."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

from .config import Config
from . import utils


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
        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=cfg.timeout,
            verify=cfg.verify_tls,
            follow_redirects=True,
            proxy=cfg.proxy,
            limits=httpx.Limits(max_connections=cfg.concurrency * 2,
                                max_keepalive_connections=cfg.concurrency),
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
