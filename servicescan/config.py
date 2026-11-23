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
    udp: bool = False                     # add -sU (UDP scan; needs root, slow)
    nse: bool = False                     # run NSE scripts (--script)
    nse_scripts: str = "vuln"             # which NSE scripts/categories to run

    # fingerprint layer
    fingerprint: bool = True              # run our own layer on unknown services
    fp_all: bool = False                  # fingerprint ALL open ports, not just unknown
    render: bool = False                  # render each web port's root (Playwright)
                                          # to catch JS-global/DOM-only catalog apps
    timeout: float = 8.0                  # per-probe timeout (s)
    concurrency: int = 50
    realm: str | None = None              # AD/Kerberos realm for the TCP-88
                                          # AS-REQ user-enum / AS-REP-roast
                                          # posture check (--realm/--domain).
                                          # When unset it is auto-derived from a
                                          # dotted-FQDN target; no realm (and a
                                          # bare-IP target) -> the check is
                                          # skipped, since the AS-REQ realm is
                                          # mandatory. No credentials are sent.
    cam_creds: bool = True                # on a gated RTSP/RTSPS stream, ONVIF
                                          # device, or vendor camera CGI, try a
                                          # tiny factory-default credential list
                                          # (admin:admin, admin:12345 ...);
                                          # --no-cam-creds disables this one active
                                          # step (read-only recon -- ONVIF enum,
                                          # snapshot, WS-Discovery, CGI info
                                          # disclosure -- still runs)

    # cve correlation
    cve: bool = True
    nvd: bool = True
    osv: bool = True
    epss: bool = True                     # enrich CVEs with FIRST.org EPSS scores
    kev: bool = True                      # flag CVEs listed in CISA KEV catalog
    exploits: bool = False                # map CVEs to public exploits/PoCs
    nvd_api_key: str | None = None        # optional, raises rate limit
    min_cvss: float = 0.0                 # filter out CVEs below this score
    kev_high_only: bool = True            # DEFAULT: human outputs show only KEV
                                          # or HIGH/CRITICAL (>=7.0) CVEs;
                                          # scan.json keeps the full set (nothing
                                          # lost). --all-cves turns this off.
    max_cves_per_service: int = 50        # DISPLAY cap (applied after KEV/EPSS
                                          # ranking, so KEV/critical survive)
    max_cve_fetch: int = 2000             # hard ceiling on CVEs pulled per NVD
                                          # query (paginated); guards pathological
                                          # products with thousands of CVEs
    cve_cache: bool = True                # cache NVD/OSV/EPSS/KEV lookups to disk
    cache_ttl: int = 86400                # cache entry lifetime (seconds)

    # web chain (--web): hand discovered HTTP(S) ports to webrecon, pivoting on
    # TLS cert SANs to enumerate cert-only / internal virtual hosts
    web: bool = False                     # run webrecon on discovered web ports
    web_render: bool = False              # use Playwright JS rendering in the chain
    web_depth: int = 1                    # crawl depth per web port
    web_max_pages: int = 60               # page cap per web port
    web_time_budget: float | None = None  # wall-clock cap (s) on each per-port
                                          # crawl; None = no limit. --full sets
                                          # 600. On a slow host the crawl stops
                                          # gracefully and returns partial results.
    write_hosts: bool = False             # append harvested cert SANs to /etc/hosts

    # output
    outdir: str = "servicescan-out"
    quiet: bool = False
    verbose: bool = False
