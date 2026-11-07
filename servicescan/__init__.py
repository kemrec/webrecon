"""servicescan — service/version discovery + CVE correlation.

Wraps nmap for port + service/version detection, then layers its own
banner-grab / HTTP / TLS fingerprinting on top to recover versions nmap
leaves as UNKNOWN. For every (product, version) it correlates known
vulnerabilities from NVD and OSV.

Ships alongside webrecon and reuses its HTTP client / utils.
"""

__version__ = "0.1.0"
