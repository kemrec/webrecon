"""Pipeline wiring all phases together.

Phase order:
  1. crawl (render + JS mining + secrets)          -> seeds hosts/urls
  2. discovery (cert SANs, crt.sh, vhost fuzz)      -> new hosts
  3. crawl discovered live hosts (shallow)          -> endpoints on vhosts/subs
  4. alive probe (urls + hosts)
  5. aggregate + report
"""
from __future__ import annotations

from .config import Config
from .http_client import HTTPClient
from .crawler import Crawler, CrawlResult
from . import discovery, alive, utils


async def run(cfg: Config) -> dict:
    primary_host = utils.host_of(cfg.target)
    if not cfg.scope_hosts:
        cfg.scope_hosts = {primary_host}

    http = HTTPClient(cfg)
    agg = CrawlResult()
    try:
        # ---- phase 1: primary crawl ----
        if cfg.do_crawl:
            utils.info(f"phase 1: crawling {cfg.target} (depth={cfg.depth})")
            async with Crawler(cfg, http) as crawler:
                r1 = await crawler.run([cfg.target])
            _merge(agg, r1)

        # ---- phase 2: discovery ----
        disco = None
        if cfg.do_subdomains or cfg.do_vhost:
            utils.info("phase 2: subdomain / cert / vhost discovery")
            disco = await discovery.run_discovery(cfg, http, primary_host, agg.hosts)

        # ---- phase 3: crawl newly discovered live hosts (shallow) ----
        new_hosts: set[str] = set()
        if disco:
            for h in disco.resolved:
                if h != primary_host and h not in cfg.scope_hosts:
                    new_hosts.add(h)
            for v in disco.vhosts:
                new_hosts.add(v["host"])

        if cfg.do_crawl and new_hosts:
            utils.info(f"phase 3: shallow crawl of {len(new_hosts)} discovered hosts")
            scheme = "https" if cfg.target.startswith("https") else "http"
            seeds = [f"{scheme}://{h}/" for h in new_hosts]
            sub_cfg = _shallow(cfg)
            sub_cfg.scope_hosts = cfg.scope_hosts | new_hosts
            async with Crawler(sub_cfg, http) as c2:
                r3 = await c2.run(seeds)
            _merge(agg, r3)

        # ---- phase 4: alive probing ----
        alive_urls, alive_hosts = [], []
        if cfg.do_alive:
            utils.info("phase 4: liveness probing")
            # probe non-JS page-like urls (cap to keep it sane)
            probe_set = {u for u in agg.urls if not utils.looks_like_js(u)}
            alive_urls = [a.to_dict() for a in await alive.probe_urls(cfg, http, probe_set)]
            if disco:
                alive_hosts = [a.to_dict()
                               for a in await alive.probe_hosts(cfg, http,
                                                                set(disco.resolved))]

        # ---- phase 5: aggregate ----
        all_subs = set()
        if disco:
            all_subs |= set(disco.crtsh_subs) | set(disco.cert_sans) | set(disco.resolved)

        data = {
            "target": cfg.target,
            "pages": agg.pages,
            "urls": sorted(agg.urls),
            "js_files": sorted(agg.js_files),
            "endpoints": sorted(agg.endpoints),
            "params": {k: sorted(v) for k, v in agg.params.items()},
            "subdomains": sorted(all_subs),
            "resolved": disco.resolved if disco else {},
            "cert_sans": disco.cert_sans if disco else [],
            "vhosts": disco.vhosts if disco else [],
            "alive_urls": alive_urls,
            "alive_hosts": alive_hosts,
            "secrets": [f.to_dict() for f in agg.secret_findings],
        }
        return data
    finally:
        await http.close()


def _merge(dst: CrawlResult, src: CrawlResult) -> None:
    dst.pages.update(src.pages)
    dst.urls |= src.urls
    dst.js_files |= src.js_files
    dst.endpoints |= src.endpoints
    dst.hosts |= src.hosts
    for ep, keys in src.params.items():
        dst.params.setdefault(ep, set()).update(keys)
    dst.secret_findings.extend(src.secret_findings)


def _shallow(cfg: Config) -> Config:
    import copy
    c = copy.copy(cfg)
    c.depth = min(cfg.depth, 1)
    c.max_pages = max(20, cfg.max_pages // 4)
    return c
