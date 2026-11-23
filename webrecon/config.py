"""Runtime configuration shared across modules."""
from __future__ import annotations

from dataclasses import dataclass, field


DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


@dataclass
class Config:
    # target
    target: str = ""                      # scheme://host or host
    scope_hosts: set[str] = field(default_factory=set)  # hosts considered in-scope

    # crawl
    depth: int = 2                        # max crawl depth
    max_pages: int = 300                  # hard cap on pages fetched
    render: bool = True                   # use Playwright JS rendering
    headful: bool = False                 # headed browser (debug)
    same_scope_only: bool = True          # only crawl in-scope hosts
    include_subdomains: bool = True       # subdomains count as in-scope
    wait_until: str = "networkidle"       # playwright nav wait state
    page_timeout: int = 20000             # ms per page
    # wall-clock budget (seconds) for the whole crawl loop. Default 300s: the
    # loop stops gracefully once the budget is spent and returns the partial
    # result gathered so far (no crash) -- a guard against a slow target stalling
    # the crawl for many minutes. Set to 0 (or None) for no limit, in which case
    # only max_pages/depth/per-request timeout bound the crawl.
    time_budget: float | None = 300.0
    # hard per-page cap (seconds). time_budget is only observed at the worker
    # loop boundary, so a single page wedged mid-fetch (e.g. a server that
    # trickles the body slower than the per-read timeout, which bounds the gap
    # between reads, not the total) would keep a worker off the boundary forever
    # and the budget would never fire. Each page is wrapped in asyncio.wait_for
    # with this cap so a stuck page is abandoned and the worker returns to check
    # the budget. None auto-sizes from page_timeout / (timeout * (retries+1)).
    page_hard_timeout: float | None = None
    # resource throttling for render mode (keeps CPU/RAM bounded):
    render_workers: int = 3               # max concurrent browser tabs/contexts
    # resource types aborted during render — we only need DOM links + JS + the
    # request URLs (captured before the abort), so images/media/fonts are pure
    # cost. Loading them is what makes a headless crawl spike CPU/memory.
    block_resources: set[str] = field(
        default_factory=lambda: {"image", "media", "font"})
    max_js_bytes: int = 20_000_000        # skip parsing JS bundles bigger than this
    save_js: bool = False                 # write fetched JS bodies to <outdir>/js
                                          # (+ manifest.tsv) for external secret
                                          # scanning, e.g. trufflehog filesystem
    secrets_aggressive: bool = False      # opt-in entropy sweep for generic secrets

    # networking
    concurrency: int = 40                 # async concurrency for probes/fetches
    timeout: float = 12.0                 # seconds per HTTP request
    # hard total cap (seconds) per fetch attempt. httpx's `timeout` bounds the
    # gap between network reads, NOT the total time, so a server that trickles
    # the body slower than `timeout` keeps a request alive forever -- which hung
    # whole scans in the non-crawl phases (alive/openapi/vhost, outside the crawl
    # budget). Every fetch attempt is wrapped in asyncio.wait_for with this cap.
    # None auto-sizes to max(timeout * 3, 30).
    request_hard_timeout: float | None = None
    retries: int = 1
    user_agent: str = DEFAULT_UA
    verify_tls: bool = False              # recon default: don't fail on bad certs
    extra_headers: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    # internal-DNS override: hostname -> IP. Requests to these hosts connect to
    # the mapped IP while keeping the hostname for the Host header + TLS SNI, so
    # names that live only in a cert (e.g. admin.corp.internal) are reachable
    # without touching /etc/hosts.
    resolve_map: dict[str, str] = field(default_factory=dict)
    # extra candidate hosts injected into the discovery/vhost phase (e.g. cert
    # SANs harvested by servicescan before handing off to webrecon).
    extra_hosts: set[str] = field(default_factory=set)

    # feature toggles
    do_crawl: bool = True
    do_js_extract: bool = True
    do_secrets: bool = True
    do_subdomains: bool = True
    do_vhost: bool = True
    do_alive: bool = True
    do_openapi: bool = True               # probe for OpenAPI/Swagger specs

    # wordlists / sources
    vhost_wordlist: str | None = None
    subdomain_wordlist: str | None = None

    # output
    outdir: str = "webrecon-out"
    json_out: bool = True
    quiet: bool = False
    verbose: bool = False
