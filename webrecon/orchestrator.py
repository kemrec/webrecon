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
        want_disco = cfg.do_subdomains or cfg.do_vhost
        # An IP literal or a dotless/local host has no registrable domain, so
        # crt.sh / cert-SAN / vhost discovery is meaningless (and previously
        # produced 'crt.sh for *.0.1' and resolved off-target public IPs).
        if want_disco and (utils.is_ip(primary_host) or "." not in primary_host):
            utils.warn("skipping discovery (subdomain/cert/vhost): target is an IP "
                       "or local host with no registrable domain")
        elif want_disco:
            utils.info("phase 2: subdomain / cert / vhost discovery")
            try:
                disco = await discovery.run_discovery(cfg, http, primary_host, agg.hosts)
            except Exception as e:  # noqa: BLE001
                # a discovery failure must never discard the crawl results
                utils.warn(f"discovery phase failed ({e}); continuing with crawl results")
                disco = None

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
            _, tgt_port = utils.hostport_of(cfg.target)
            seeds = [f"{scheme}://{utils.with_port(h, tgt_port)}/" for h in new_hosts]
            sub_cfg = _shallow(cfg)
            sub_cfg.scope_hosts = cfg.scope_hosts | new_hosts
            async with Crawler(sub_cfg, http) as c2:
                r3 = await c2.run(seeds)
            _merge(agg, r3)

        # ---- phase 4: alive probing ----
        alive_urls, alive_hosts = [], []
        if cfg.do_alive:
            utils.info("phase 4: liveness probing")
            # probe non-JS page-like urls (cap to keep it sane). Off-target
            # referenced URLs stay recorded in urls.txt but are NOT probed when
            # scope confinement is on -- no active traffic to third-party hosts.
            probe_set = {u for u in agg.urls if not utils.looks_like_js(u)}
            if cfg.same_scope_only:
                probe_set = {u for u in probe_set
                             if utils.in_scope(u, cfg.scope_hosts,
                                               cfg.include_subdomains)}
            alive_urls = [a.to_dict() for a in await alive.probe_urls(cfg, http, probe_set)]
            if disco:
                alive_hosts = [a.to_dict()
                               for a in await alive.probe_hosts(cfg, http,
                                                                set(disco.resolved))]

        # ---- phase 5: aggregate ----
        all_subs = set()
        if disco:
            all_subs |= set(disco.crtsh_subs) | set(disco.cert_sans) | set(disco.resolved)

        # Scope-confine the ATTACK-SURFACE outputs. The crawler records off-scope
        # references (third-party / CDN / public URLs seen on target pages) in
        # agg.urls as intel, but it never fetches them -- and they must NOT leak
        # into urls.txt / endpoints.txt / params.txt / forms.txt, which feed
        # Burp / ffuf / sqlmap. Actively fuzzing a public host you were not
        # scoped to is both noise and an authorization problem. Keep only
        # in-scope entries here; preserve the off-scope ones under
        # "external_urls" so the intel is not lost.
        in_urls = sorted(u for u in agg.urls if _out_scope(u, cfg))
        ext_urls = sorted(u for u in agg.urls if not _out_scope(u, cfg))
        in_endpoints = sorted(e for e in agg.endpoints if _out_scope(e, cfg))
        in_params = {k: sorted(v) for k, v in agg.params.items() if _out_scope(k, cfg)}
        in_forms = [f for f in agg.forms if _out_scope(f.get("url", ""), cfg)]

        data = {
            "target": cfg.target,
            "pages": agg.pages,
            "urls": in_urls,
            "external_urls": ext_urls,
            "js_files": sorted(agg.js_files),
            "endpoints": in_endpoints,
            "params": in_params,
            "subdomains": sorted(all_subs),
            "resolved": disco.resolved if disco else {},
            "cert_sans": disco.cert_sans if disco else [],
            "vhosts": disco.vhosts if disco else [],
            "alive_urls": alive_urls,
            "alive_hosts": alive_hosts,
            "secrets": [f.to_dict() for f in agg.secret_findings],
            "tech": sorted(agg.tech),
            "forms": in_forms,
        }
        return data
    finally:
        await http.close()


def _out_scope(u: str, cfg: Config) -> bool:
    """True if a URL / endpoint belongs in the scope-confined attack-surface
    output. Hostless (relative) endpoints like '/api/x' belong to the target
    and are always kept. An absolute URL is kept only when its host is in scope.
    With same_scope_only off, everything is kept."""
    if not cfg.same_scope_only:
        return True
    if not utils.host_of(u):
        return True   # relative / hostless endpoint -> belongs to the target
    return utils.in_scope(u, cfg.scope_hosts, cfg.include_subdomains)


def _merge(dst: CrawlResult, src: CrawlResult) -> None:
    dst.pages.update(src.pages)
    dst.urls |= src.urls
    dst.js_files |= src.js_files
    dst.endpoints |= src.endpoints
    dst.hosts |= src.hosts
    for ep, keys in src.params.items():
        dst.params.setdefault(ep, set()).update(keys)
    dst.secret_findings.extend(src.secret_findings)
    dst.tech |= src.tech
    dst.forms.extend(src.forms)


def _shallow(cfg: Config) -> Config:
    import copy
    c = copy.copy(cfg)
    c.depth = min(cfg.depth, 1)
    c.max_pages = max(20, cfg.max_pages // 4)
    return c
