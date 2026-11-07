"""Shared data models across servicescan phases."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class Service:
    """A single open port and what we know is running on it."""
    port: int
    proto: str = "tcp"                 # tcp | udp
    state: str = "open"
    # service identity (best merged guess)
    name: str = ""                     # e.g. http, ssh, mysql
    product: str = ""                  # e.g. nginx, OpenSSH, Apache httpd
    version: str = ""                  # e.g. 1.18.0
    extrainfo: str = ""                # OS/module hints
    cpe: list[str] = field(default_factory=list)
    # provenance: where each piece of info came from (nmap / banner / http / tls)
    sources: list[str] = field(default_factory=list)
    confidence: str = "low"            # low | medium | high
    banner: str = ""                   # raw banner snippet (redacted/truncated)
    tls: dict = field(default_factory=dict)   # cert subject/issuer/SANs if TLS
    http: dict = field(default_factory=dict)  # server header, title, tech hints
    cves: list["CVE"] = field(default_factory=list)
    web: dict = field(default_factory=dict)   # webrecon results (--web chain)

    def ident(self) -> str:
        v = f" {self.version}" if self.version else ""
        return f"{self.product or self.name or '?'}{v}".strip()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cves"] = [c.to_dict() if isinstance(c, CVE) else c for c in self.cves]
        return d


@dataclass
class CVE:
    id: str                             # CVE-2021-41773
    source: str                         # nvd | osv
    cvss: float | None = None           # base score (prefer v3.1)
    severity: str = ""                  # CRITICAL/HIGH/MEDIUM/LOW/NONE
    summary: str = ""                   # short description
    url: str = ""                       # reference / advisory link
    published: str = ""                 # date string
    epss: float | None = None           # EPSS exploitation probability (0..1)
    epss_pct: float | None = None       # EPSS percentile among all CVEs (0..1)
    kev: bool = False                   # listed in CISA KEV (known exploited)
    exploits: list = field(default_factory=list)  # [{source,title,url}] public PoCs

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Host:
    """One scanned host (an IP, optionally with the hostname it came from)."""
    target: str = ""                   # token that produced it (IP or hostname)
    ip: str = ""                       # resolved / scanned IP
    hostname: str = ""                 # user-supplied or PTR hostname, if any
    services: list["Service"] = field(default_factory=list)

    def label(self) -> str:
        if self.hostname and self.ip and self.hostname != self.ip:
            return f"{self.hostname} ({self.ip})"
        return self.ip or self.hostname or self.target

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "ip": self.ip,
            "hostname": self.hostname,
            "services": [s.to_dict() for s in self.services],
        }


@dataclass
class ScanResult:
    target: str                                       # original spec (display)
    hosts: list[Host] = field(default_factory=list)
    nmap_used: bool = False
    errors: list[str] = field(default_factory=list)

    # ---- backward-compatible flattened views (read-only) ----
    @property
    def services(self) -> list[Service]:
        return [s for h in self.hosts for s in h.services]

    @property
    def ip(self) -> str:
        for h in self.hosts:
            if h.ip:
                return h.ip
        return ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "nmap_used": self.nmap_used,
            "errors": self.errors,
            "hosts": [h.to_dict() for h in self.hosts],
        }
