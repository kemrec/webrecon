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

    # networking
    concurrency: int = 40                 # async concurrency for probes/fetches
    timeout: float = 12.0                 # seconds per HTTP request
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

    # wordlists / sources
    vhost_wordlist: str | None = None
    subdomain_wordlist: str | None = None

    # output
    outdir: str = "webrecon-out"
    json_out: bool = True
    quiet: bool = False
    verbose: bool = False
