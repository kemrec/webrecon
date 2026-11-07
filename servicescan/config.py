"""Runtime configuration for servicescan."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    # target
    target: str = ""                      # IP or hostname

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
    nvd_api_key: str | None = None        # optional, raises rate limit
    min_cvss: float = 0.0                 # filter out CVEs below this score
    max_cves_per_service: int = 50

    # output
    outdir: str = "servicescan-out"
    quiet: bool = False
    verbose: bool = False
