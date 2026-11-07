"""BFS crawler with optional Playwright JS rendering.

Strategy per page:
  1. Render with headless/headed Chromium (if cfg.render) OR plain HTTP GET.
  2. Collect: links from DOM, network-requested URLs, inline + external JS.
  3. Fetch external JS, extract endpoints/params/secrets.
  4. Enqueue in-scope links up to cfg.depth / cfg.max_pages.

Produces a CrawlResult aggregating everything for downstream modules.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from .config import Config
from .http_client import HTTPClient
from . import utils, extract, secrets


@dataclass
class CrawlResult:
    pages: dict[str, int] = field(default_factory=dict)        # url -> status
    urls: set[str] = field(default_factory=set)                # all discovered URLs
    js_files: set[str] = field(default_factory=set)            # external JS URLs
    endpoints: set[str] = field(default_factory=set)           # endpoint-ish strings
    params: dict[str, set[str]] = field(default_factory=dict)  # endpoint -> param names
    secret_findings: list = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)               # hosts seen (vhost seeds)


class Crawler:
    def __init__(self, cfg: Config, http: HTTPClient):
        self.cfg = cfg
        self.http = http
        self.result = CrawlResult()
        self._browser = None
        self._pw = None

    async def __aenter__(self):
        if self.cfg.render:
            await self._start_browser()
        return self

    async def __aexit__(self, *exc):
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.stop()

    async def _start_browser(self):
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            utils.warn("playwright not installed; falling back to HTTP-only crawl")
            self.cfg.render = False
            return
        args = ["--no-sandbox", "--disable-dev-shm-usage",
                "--ignore-certificate-errors"]
        # mirror the httpx DNS override into Chromium so rendered requests to
        # mapped hostnames also hit the chosen IP.
        resolve_map = getattr(self.cfg, "resolve_map", None)
        if resolve_map:
            rules = ",".join(f"MAP {h} {ip}" for h, ip in resolve_map.items())
            args.append(f"--host-resolver-rules={rules}")
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(
            headless=not self.cfg.headful,
            args=args,
        )
        utils.info(f"browser launched (headless={not self.cfg.headful})")

    # -- rendering -----------------------------------------------------------
    async def _render(self, url: str) -> tuple[int, str, set[str]]:
        """Return (status, html, network_urls) using Playwright."""
        net_urls: set[str] = set()
        ctx = await self._browser.new_context(
            user_agent=self.cfg.user_agent,
            ignore_https_errors=True,
            extra_http_headers=self.cfg.extra_headers or None,
        )
        page = await ctx.new_page()
        status = 0
        page.on("request", lambda req: net_urls.add(req.url))
        try:
            resp = await page.goto(url, wait_until=self.cfg.wait_until,
                                   timeout=self.cfg.page_timeout)
            status = resp.status if resp else 0
            # small settle for lazy JS
            try:
                await page.wait_for_timeout(600)
            except Exception:
                pass
            html = await page.content()
        except Exception as e:  # noqa: BLE001
            utils.debug(f"render failed {url}: {type(e).__name__}")
            html = ""
        finally:
            await ctx.close()
        return status, html, net_urls

    # -- per-page processing -------------------------------------------------
    async def _process_js(self, js_url: str) -> None:
        if js_url in self.result.js_files:
            return
        self.result.js_files.add(js_url)
        r = await self.http.fetch(js_url)
        if not r.ok or not r.text:
            return
        raw = extract.extract_js_endpoints(r.text)
        urls, pkeys, unresolved = extract.resolve_and_classify(js_url, raw)
        self.result.urls |= urls
        self.result.endpoints |= unresolved
        for ep, keys in pkeys.items():
            self.result.params.setdefault(ep, set()).update(keys)
        for u in urls:
            self.result.hosts.add(utils.host_of(u))
        if self.cfg.do_secrets:
            self.result.secret_findings.extend(secrets.scan(r.text, js_url))

    async def _process_page(self, url: str, depth: int, queue: asyncio.Queue,
                            visited: set[str]) -> None:
        # render or plain GET
        if self.cfg.render and self._browser:
            status, html, net_urls = await self._render(url)
        else:
            r = await self.http.fetch(url)
            status, html, net_urls = r.status, r.text, set()

        self.result.pages[url] = status
        self.result.hosts.add(utils.host_of(url))
        if not html:
            return

        # secrets in HTML / inline scripts
        if self.cfg.do_secrets:
            self.result.secret_findings.extend(secrets.scan(html, url))

        # gather raw links
        raw_links = extract.extract_html_links(html)
        raw_links |= extract.extract_js_endpoints(html)  # inline JS
        for n in net_urls:
            raw_links.add(n)

        urls, pkeys, unresolved = extract.resolve_and_classify(url, raw_links)
        self.result.urls |= urls
        self.result.endpoints |= unresolved
        for ep, keys in pkeys.items():
            self.result.params.setdefault(ep, set()).update(keys)

        # schedule external JS for endpoint/secret mining
        js_tasks = []
        for u in urls:
            self.result.hosts.add(utils.host_of(u))
            if utils.looks_like_js(u) and self.cfg.do_js_extract:
                js_tasks.append(self._process_js(u))
        if js_tasks:
            await asyncio.gather(*js_tasks)

        # enqueue in-scope links for further crawling
        if depth < self.cfg.depth:
            for u in urls:
                if u in visited:
                    continue
                if utils.looks_like_js(u):
                    continue
                if self.cfg.same_scope_only and not utils.in_scope(
                    u, self.cfg.scope_hosts, self.cfg.include_subdomains
                ):
                    continue
                if len(visited) + queue.qsize() >= self.cfg.max_pages:
                    break
                await queue.put((u, depth + 1))

    async def run(self, seeds: list[str]) -> CrawlResult:
        queue: asyncio.Queue = asyncio.Queue()
        visited: set[str] = set()
        for s in seeds:
            await queue.put((s, 0))

        async def worker():
            while True:
                try:
                    url, depth = await asyncio.wait_for(queue.get(), timeout=2.0)
                except asyncio.TimeoutError:
                    return
                try:
                    if url in visited or len(visited) >= self.cfg.max_pages:
                        continue
                    visited.add(url)
                    utils.info(f"crawl d{depth} [{len(visited)}/{self.cfg.max_pages}] {url}")
                    await self._process_page(url, depth, queue, visited)
                except Exception as e:  # noqa: BLE001
                    utils.debug(f"page error {url}: {e}")
                finally:
                    queue.task_done()

        # render-mode: fewer workers (browser contexts are heavy); http: more
        n_workers = 3 if (self.cfg.render and self._browser) else min(self.cfg.concurrency, 15)
        workers = [asyncio.create_task(worker()) for _ in range(n_workers)]
        await asyncio.gather(*workers)

        utils.good(f"crawl done: {len(self.result.pages)} pages, "
                   f"{len(self.result.urls)} urls, {len(self.result.js_files)} JS files")
        return self.result
