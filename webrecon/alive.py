"""Liveness probing: which URLs / hosts are actually live, with status + title."""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, asdict

from .config import Config
from .http_client import HTTPClient
from . import utils

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


@dataclass
class Alive:
    url: str
    status: int
    final_url: str
    length: int
    title: str
    server: str
    content_type: str

    def to_dict(self):
        return asdict(self)


async def probe_urls(cfg: Config, http: HTTPClient, urls: set[str]) -> list[Alive]:
    """Probe each URL once; return live ones (status > 0)."""
    results: list[Alive] = []

    async def one(u: str):
        r = await http.fetch(u, method="GET", read_body=True)
        if not r.ok or r.status == 0:
            return
        title = ""
        m = _TITLE.search(r.text or "")
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        results.append(Alive(
            url=u, status=r.status, final_url=r.final_url,
            length=len(r.text or ""), title=title,
            server=r.headers.get("server", ""),
            content_type=r.content_type,
        ))

    await asyncio.gather(*(one(u) for u in urls))
    results.sort(key=lambda a: (a.status, a.url))
    utils.good(f"alive: {len(results)}/{len(urls)} URLs responded")
    return results


async def probe_hosts(cfg: Config, http: HTTPClient,
                      hosts: set[str]) -> list[Alive]:
    """Probe hostnames on https then http; return live hosts."""
    results: list[Alive] = []

    async def one(h: str):
        for scheme in ("https", "http"):
            url = f"{scheme}://{h}/"
            r = await http.fetch(url, method="GET", read_body=True)
            if r.ok and r.status > 0:
                title = ""
                m = _TITLE.search(r.text or "")
                if m:
                    title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
                results.append(Alive(
                    url=url, status=r.status, final_url=r.final_url,
                    length=len(r.text or ""), title=title,
                    server=r.headers.get("server", ""),
                    content_type=r.content_type,
                ))
                return  # first working scheme wins

    await asyncio.gather(*(one(h) for h in hosts))
    results.sort(key=lambda a: a.url)
    utils.good(f"alive hosts: {len(results)}/{len(hosts)}")
    return results
