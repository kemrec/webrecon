"""Runtime configuration for servicescan."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    # target
    target: str = ""                      # original spec, for display
    targets: list[str] = field(default_factory=list)  # one or more tokens:
    #   IP / hostname / CIDR (10.0.0.0/24) / range (10.0.0.1-50); nmap expands
    #   these natively, the no-nmap fallback expands them via targets.expand()

    # port scan
    ports: str = "-"                      # nmap -p spec; "-" == all 65535
    use_nmap: bool = True                 # wrap nmap if available
    nmap_path: str = "nmap"
    nmap_args: list[str] = field(default_factory=list)  # extra nmap flags
    scan_rate: int | None = None          # nmap --min-rate
    top_ports: int | None = None          # nmap --top-ports (overrides ports)

    # fingerprint layer
    fingerprint: bool = True              # run our own layer on unknown services
    fp_all: bool = False                  # fingerprint ALL open ports, not just unknown
    timeout: float = 8.0                  # per-probe timeout (s)
    concurrency: int = 50

    # cve correlation
    cve: bool = True
    nvd: bool = True
    osv: bool = True
    epss: bool = True                     # enrich CVEs with FIRST.org EPSS scores
    kev: bool = True                      # flag CVEs listed in CISA KEV catalog
    exploits: bool = False                # map CVEs to public exploits/PoCs
    nvd_api_key: str | None = None        # optional, raises rate limit
    min_cvss: float = 0.0                 # filter out CVEs below this score
    max_cves_per_service: int = 50
    cve_cache: bool = True                # cache NVD/OSV/EPSS/KEV lookups to disk
    cache_ttl: int = 86400                # cache entry lifetime (seconds)

    # web chain (--web): hand discovered HTTP(S) ports to webrecon, pivoting on
    # TLS cert SANs to enumerate cert-only / internal virtual hosts
    web: bool = False                     # run webrecon on discovered web ports
    web_render: bool = False              # use Playwright JS rendering in the chain
    web_depth: int = 1                    # crawl depth per web port
    web_max_pages: int = 60               # page cap per web port
    write_hosts: bool = False             # append harvested cert SANs to /etc/hosts

    # output
    outdir: str = "servicescan-out"
    quiet: bool = False
    verbose: bool = False
