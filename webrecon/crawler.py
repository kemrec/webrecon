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
import hashlib
import os
import re as _re
import time
from dataclasses import dataclass, field

from .config import Config
from .http_client import HTTPClient
from . import utils, extract, secrets, tech


def js_filename(url: str) -> str:
    """Deterministic, collision-safe local filename for a saved JS URL. Keeps a
    readable host_path stem (so the file is recognisable on disk) plus a short
    hash of the full URL so two different URLs never map to one file."""
    h = hashlib.sha1(url.encode("utf-8", "replace")).hexdigest()[:10]
    stem = _re.sub(r"^https?://", "", url)
    stem = _re.sub(r"[?#].*$", "", stem)          # drop query/fragment
    stem = _re.sub(r"[^A-Za-z0-9._-]", "_", stem)  # fs-safe
    stem = stem[:80].strip("._-") or "js"
    if not stem.endswith(".js"):
        stem += ".js"
    return f"{stem}.{h}.js"


# Clock indirection so tests can drive the crawl time-budget deterministically
# without monkeypatching the stdlib `time.monotonic` (which asyncio itself uses).
_monotonic = time.monotonic


# Lazy handle to servicescan's shared technology catalog + matcher. Imported on
# demand so webrecon has no import-time dependency on servicescan.
_CATMOD = None


def _catmod():
    global _CATMOD
    if _CATMOD is None:
        try:
            from servicescan import fingerprint as _fp
            _CATMOD = _fp
        except Exception:  # noqa: BLE001
            _CATMOD = False
    return _CATMOD


@dataclass
class CrawlResult:
    pages: dict[str, int] = field(default_factory=dict)        # url -> status
    urls: set[str] = field(default_factory=set)                # all discovered URLs
    js_files: set[str] = field(default_factory=set)            # external JS URLs
    js_sources: dict[str, set[str]] = field(default_factory=dict)  # JS URL -> pages that referenced it
    endpoints: set[str] = field(default_factory=set)           # endpoint-ish strings
    params: dict[str, set[str]] = field(default_factory=dict)  # endpoint -> param names
    secret_findings: list = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)               # hosts seen (vhost seeds)
    tech: set[str] = field(default_factory=set)                # detected technologies
    forms: list = field(default_factory=list)                  # {url,method,params}


class Crawler:
    def __init__(self, cfg: Config, http: HTTPClient, control=None):
        self.cfg = cfg
        self.http = http
        self.control = control            # optional ScanControl (pause/stop)
        self.result = CrawlResult()
        self._browser = None
        self._pw = None
        self._cat_specs = None            # cached (js_vars, dom_specs)
        self._js_dir = None               # <outdir>/js, created lazily on first save
        self._js_saved: set[str] = set()  # JS URLs whose body we wrote to disk

    async def __aenter__(self):
        if self.cfg.render:
            await self._start_browser()
        return self

    async def __aexit__(self, *exc):
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.stop()

    # -- technology catalog --------------------------------------------------
    def _catalog_specs(self):
        """(js_vars, dom_specs) the catalog wants evaluated on a rendered page;
        cached. Empty when the catalog is unavailable."""
        if self._cat_specs is None:
            fp = _catmod()
            if fp:
                self._cat_specs = (fp.catalog_js_vars(), fp.catalog_dom_specs())
            else:
                self._cat_specs = ([], [])
        return self._cat_specs

    def _apply_catalog(self, headers, html, js_globals, dom_eval) -> None:
        """Run the shared 299-app catalog over a page and fold the hits into
        result.tech as 'Name version' labels. js_globals/dom_eval are None on a
        plain GET, so only the static (header/meta/html/cookie) sigs fire there;
        on a rendered page the JS-global / DOM sigs fire too."""
        fp = _catmod()
        if not fp:
            return
        try:
            for name, ver in fp.match_catalog(headers or {}, html or "",
                                              js_globals=js_globals,
                                              dom_eval=dom_eval):
                self.result.tech.add(f"{name} {ver}".strip())
        except Exception as e:  # noqa: BLE001
            utils.debug(f"catalog match: {type(e).__name__}")

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
    async def _route(self, route) -> None:
        """Abort heavy, discovery-irrelevant resources (images/media/fonts)."""
        try:
            if route.request.resource_type in self.cfg.block_resources:
                await route.abort()
            else:
                await route.continue_()
        except Exception:  # noqa: BLE001
            try:
                await route.continue_()
            except Exception:  # noqa: BLE001
                pass

    async def _render(self, url: str) -> tuple[int, str, set[str], dict, dict, dict]:
        """Return (status, html, network_urls, headers, js_globals, dom_eval)
        using Playwright. js_globals/dom_eval carry the rendered-page technology
        signals (JS global vars, DOM selectors) the catalog matcher consumes."""
        net_urls: set[str] = set()
        headers: dict = {}
        js_globals: dict = {}
        dom_eval: dict = {}
        ctx = await self._browser.new_context(
            user_agent=self.cfg.user_agent,
            ignore_https_errors=True,
            extra_http_headers=self.cfg.extra_headers or None,
        )
        page = await ctx.new_page()
        status = 0
        # record every request URL (fires before routing, so blocked resources
        # are still discovered) then drop the heavy ones to save CPU/memory.
        page.on("request", lambda req: net_urls.add(req.url))
        if self.cfg.block_resources:
            await ctx.route("**/*", self._route)
        try:
            resp = await page.goto(url, wait_until=self.cfg.wait_until,
                                   timeout=self.cfg.page_timeout)
            status = resp.status if resp else 0
            if resp:
                try:
                    headers = dict(resp.headers)
                except Exception:  # noqa: BLE001
                    headers = {}
            # small settle for lazy JS
            try:
                await page.wait_for_timeout(600)
            except Exception:
                pass
            html = await page.content()
            # evaluate the catalog's JS-global / DOM signals on the live page
            try:
                from . import render as _render_mod
                js_vars, dom_specs = self._catalog_specs()
                js_globals, dom_eval = await _render_mod.eval_specs(
                    page, js_vars, dom_specs)
            except Exception as e:  # noqa: BLE001
                utils.debug(f"catalog eval {url}: {type(e).__name__}")
        except Exception as e:  # noqa: BLE001
            utils.debug(f"render failed {url}: {type(e).__name__}")
            html = ""
        finally:
            await ctx.close()
        return status, html, net_urls, headers, js_globals, dom_eval

    # -- per-page processing -------------------------------------------------
    def _in_scope(self, u: str) -> bool:
        """Whether a URL's host is in crawl scope (fetch/secret-scan/vhost-seed
        gate). When same_scope_only is off, everything is in scope."""
        if not self.cfg.same_scope_only:
            return True
        return utils.in_scope(u, self.cfg.scope_hosts, self.cfg.include_subdomains)

    def _save_js(self, js_url: str, text: str) -> None:
        """Write a fetched JS body under <outdir>/js so an external secret
        scanner (trufflehog filesystem mode) can sweep the full bundle text.
        No-op unless cfg.save_js is set. Filename preserves provenance via the
        js/manifest.tsv written at end of run()."""
        if not getattr(self.cfg, "save_js", False) or not self.cfg.outdir:
            return
        try:
            if self._js_dir is None:
                self._js_dir = os.path.join(self.cfg.outdir, "js")
                os.makedirs(self._js_dir, exist_ok=True)
            with open(os.path.join(self._js_dir, js_filename(js_url)),
                      "w", encoding="utf-8") as fh:
                fh.write(text)
            self._js_saved.add(js_url)
        except Exception as e:  # noqa: BLE001
            utils.debug(f"save js {js_url}: {type(e).__name__}: {e}")

    def _write_js_manifest(self) -> None:
        """Map every saved JS file back to its URL and the page(s) that linked
        it, so a secret found by trufflehog in js/<file> is instantly traced to
        its origin (the IP:port is already the enclosing output directory)."""
        if not self._js_saved or not self._js_dir:
            return
        try:
            rows = ["filename\tjs_url\treferenced_from"]
            for u in sorted(self._js_saved):
                parents = ",".join(sorted(self.result.js_sources.get(u, [])))
                rows.append(f"{js_filename(u)}\t{u}\t{parents}")
            with open(os.path.join(self._js_dir, "manifest.tsv"),
                      "w", encoding="utf-8") as fh:
                fh.write("\n".join(rows) + "\n")
        except Exception as e:  # noqa: BLE001
            utils.debug(f"js manifest: {type(e).__name__}: {e}")

    async def _process_js(self, js_url: str, parent: str | None = None) -> None:
        # record provenance for EVERY referencing page, before the dedup return
        if parent:
            self.result.js_sources.setdefault(js_url, set()).add(parent)
        if js_url in self.result.js_files:
            return
        self.result.js_files.add(js_url)
        r = await self.http.fetch(js_url)
        if not r.ok or not r.text:
            return
        # save the full body first (even oversized bundles -- a prime place for
        # buried keys), then skip only the in-process parse of huge files.
        self._save_js(js_url, r.text)
        if len(r.text) > self.cfg.max_js_bytes:
            utils.debug(f"skip large JS ({len(r.text)}B > "
                        f"{self.cfg.max_js_bytes}B cap) {js_url}")
            return
        raw = extract.extract_js_endpoints(r.text)
        urls, pkeys, unresolved = extract.resolve_and_classify(js_url, raw)
        self.result.urls |= urls
        self.result.endpoints |= unresolved
        for ep, keys in pkeys.items():
            self.result.params.setdefault(ep, set()).update(keys)
        for u in urls:
            if self._in_scope(u):
                self.result.hosts.add(utils.host_of(u))
        if self.cfg.do_secrets:
            self.result.secret_findings.extend(
                secrets.scan(r.text, js_url, self.cfg.secrets_aggressive))

    async def _process_page(self, url: str, depth: int, queue: asyncio.Queue,
                            visited: set[str]) -> None:
        # render or plain GET
        if self.cfg.render and self._browser:
            status, html, net_urls, headers, js_globals, dom_eval = \
                await self._render(url)
        else:
            r = await self.http.fetch(url)
            status, html, net_urls, headers = r.status, r.text, set(), r.headers
            js_globals, dom_eval = None, None

        self.result.pages[url] = status
        self.result.hosts.add(utils.host_of(url))
        if not html:
            return

        # technology fingerprint (headers + body), best-effort: the hand-written
        # sigs plus the shared 299-app catalog (static here, JS-global/DOM too
        # when the page was rendered).
        try:
            self.result.tech |= tech.detect(headers, html)
        except Exception as e:  # noqa: BLE001
            utils.debug(f"tech {url}: {e}")
        self._apply_catalog(headers, html, js_globals, dom_eval)

        # HTML forms -> endpoints + parameters
        for f in extract.extract_forms(html):
            action = utils.normalize_url(url, f["action"]) if f["action"] else url
            action = action or url
            self.result.forms.append({"url": action, "method": f["method"],
                                      "params": f["params"]})
            if action.startswith("http"):
                self.result.urls.add(action)
                clean, _ = utils.split_params(action)
                if f["params"]:
                    self.result.params.setdefault(clean, set()).update(f["params"])

        # secrets in HTML / inline scripts
        if self.cfg.do_secrets:
            self.result.secret_findings.extend(
                secrets.scan(html, url, self.cfg.secrets_aggressive))

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

        # schedule JS for endpoint/secret mining -- ONLY for in-scope hosts.
        # Off-origin links (github.com, CDNs, shields.io ...) stay recorded in
        # result.urls as discovered references, but we never FETCH or secret-scan
        # them (that produced third-party false-positive secrets and off-target
        # traffic), and we never seed the vhost phase with their hosts.
        js_tasks = []
        for u in urls:
            if not self._in_scope(u):
                continue
            self.result.hosts.add(utils.host_of(u))
            if utils.looks_like_js(u) and self.cfg.do_js_extract:
                js_tasks.append(self._process_js(u, parent=url))
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
        progress = utils.Progress("crawl")
        for s in seeds:
            await queue.put((s, 0))

        # wall-clock budget: stop the loop gracefully once spent and return the
        # partial result. None == unlimited (historical behaviour).
        budget = self.cfg.time_budget
        deadline = (_monotonic() + budget) if budget else None
        budget_hit = False

        # hard per-page cap so a page wedged mid-fetch can't keep a worker off
        # the budget check forever. Auto-size to comfortably exceed a legitimate
        # slow page (render goto, or all fetch retries) when not set explicitly.
        page_cap = self.cfg.page_hard_timeout or (
            max(self.cfg.page_timeout / 1000.0,
                self.cfg.timeout * (self.cfg.retries + 1)) + 20.0)

        async def worker():
            nonlocal budget_hit
            while True:
                # cooperative pause/stop at the loop boundary (never mid-page):
                # a stop ends this worker gracefully (partial crawl result, like
                # the budget); a pause holds here until resumed or stopped.
                ctl = self.control
                if ctl is not None:
                    if ctl.stopped:
                        return
                    while ctl.paused:
                        await asyncio.sleep(0.15)
                        if ctl.stopped:
                            return
                # check the budget at the loop boundary (never mid-page) so a
                # stopping worker holds no queue item and overshoots by at most
                # one in-flight page (bounded by page_timeout).
                if deadline is not None and _monotonic() >= deadline:
                    budget_hit = True
                    return
                try:
                    url, depth = await asyncio.wait_for(queue.get(), timeout=2.0)
                except asyncio.TimeoutError:
                    return
                try:
                    if url in visited or len(visited) >= self.cfg.max_pages:
                        continue
                    visited.add(url)
                    progress.update(len(visited), self.cfg.max_pages, f"d{depth}")
                    utils.debug(f"crawl d{depth} [{len(visited)}/{self.cfg.max_pages}] {url}")
                    # hard cap: a page that wedges (slow-trickle body, render
                    # stall) is abandoned so the worker returns to the loop
                    # boundary and the time budget can actually fire.
                    await asyncio.wait_for(
                        self._process_page(url, depth, queue, visited),
                        timeout=page_cap)
                except asyncio.TimeoutError:
                    utils.debug(f"page hard-timeout ({page_cap:g}s), abandoned {url}")
                except Exception as e:  # noqa: BLE001
                    utils.debug(f"page error {url}: {e}")
                finally:
                    queue.task_done()

        # render-mode: fewer workers (browser contexts are heavy); http: more
        n_workers = (max(1, self.cfg.render_workers)
                     if (self.cfg.render and self._browser)
                     else min(self.cfg.concurrency, 15))
        workers = [asyncio.create_task(worker()) for _ in range(n_workers)]
        if deadline is not None:
            # hard backstop: even if a worker wedges somewhere the per-page cap
            # doesn't cover (e.g. browser context teardown), force-cancel once
            # the budget plus one page_cap of grace is spent, so the crawl can
            # never hang indefinitely past its budget.
            try:
                await asyncio.wait_for(
                    asyncio.gather(*workers),
                    timeout=max(0.0, deadline - _monotonic()) + page_cap + 5.0)
            except asyncio.TimeoutError:
                budget_hit = True
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
        else:
            await asyncio.gather(*workers)

        progress.finish()
        if budget_hit:
            utils.warn(f"crawl time budget ({budget:g}s) reached; returning "
                       f"partial result ({len(self.result.pages)} pages crawled)")
        self._write_js_manifest()
        if self._js_saved:
            utils.good(f"saved {len(self._js_saved)} JS file(s) -> {self._js_dir}/ "
                       f"(+ manifest.tsv)")
        utils.good(f"crawl done: {len(self.result.pages)} pages, "
                   f"{len(self.result.urls)} urls, {len(self.result.js_files)} JS files")
        return self.result
