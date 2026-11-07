"""Command-line interface for servicescan."""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

from .config import ScanConfig
from . import orchestrator, report
from webrecon import utils


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="servicescan",
        description="Service/version discovery (nmap + own fingerprint layer) "
                    "with NVD/OSV CVE correlation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  servicescan 10.0.0.5                      # full-port nmap + fp + CVEs
  servicescan scanme.nmap.org -p 1-1000     # port range
  servicescan 10.0.0.5 --top-ports 1000 --rate 2000
  servicescan host --no-nmap                # fingerprint-only (no nmap)
  servicescan host --no-cve                 # just service/version detection
  servicescan host --fp-all --min-cvss 7    # fingerprint every port, only high CVEs
  NVD_API_KEY=xxxx servicescan host         # raise NVD rate limit
""",
    )
    p.add_argument("target", help="IP or hostname")

    sc = p.add_argument_group("port scan")
    sc.add_argument("-p", "--ports", default="-",
                    help="nmap port spec (default '-' = all 65535)")
    sc.add_argument("--top-ports", type=int, default=None,
                    help="scan N most common ports instead")
    sc.add_argument("--rate", type=int, default=None, help="nmap --min-rate")
    sc.add_argument("--no-nmap", action="store_true",
                    help="don't use nmap; fingerprint-only on common/-p ports")
    sc.add_argument("--nmap-path", default="nmap")
    sc.add_argument("--nmap-arg", action="append", default=[],
                    metavar="ARG", help="extra nmap flag (repeatable)")

    fp = p.add_argument_group("fingerprint")
    fp.add_argument("--no-fingerprint", action="store_true",
                    help="skip our fingerprint gap-fill layer")
    fp.add_argument("--fp-all", action="store_true",
                    help="fingerprint ALL open ports, not just nmap-unknown ones")

    cv = p.add_argument_group("cve")
    cv.add_argument("--no-cve", action="store_true", help="skip CVE correlation")
    cv.add_argument("--no-nvd", action="store_true", help="skip NVD source")
    cv.add_argument("--no-osv", action="store_true", help="skip OSV source")
    cv.add_argument("--no-epss", action="store_true",
                    help="skip EPSS enrichment (FIRST.org exploit-probability)")
    cv.add_argument("--no-kev", action="store_true",
                    help="skip CISA KEV lookup (known-exploited flagging)")
    cv.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"),
                    help="NVD API key (or env NVD_API_KEY)")
    cv.add_argument("--min-cvss", type=float, default=0.0,
                    help="drop CVEs below this base score")

    net = p.add_argument_group("network")
    net.add_argument("-c", "--concurrency", type=int, default=50)
    net.add_argument("-t", "--timeout", type=float, default=8.0)

    o = p.add_argument_group("output")
    o.add_argument("-o", "--outdir", default="servicescan-out")
    o.add_argument("-q", "--quiet", action="store_true")
    o.add_argument("-v", "--verbose", action="store_true")
    return p


def cfg_from_args(a: argparse.Namespace) -> ScanConfig:
    return ScanConfig(
        target=a.target,
        ports=a.ports,
        top_ports=a.top_ports,
        scan_rate=a.rate,
        use_nmap=not a.no_nmap,
        nmap_path=a.nmap_path,
        nmap_args=a.nmap_arg,
        fingerprint=not a.no_fingerprint,
        fp_all=a.fp_all,
        cve=not a.no_cve,
        nvd=not a.no_nvd,
        osv=not a.no_osv,
        epss=not a.no_epss,
        kev=not a.no_kev,
        nvd_api_key=a.nvd_api_key,
        min_cvss=a.min_cvss,
        concurrency=a.concurrency,
        timeout=a.timeout,
        outdir=a.outdir,
        quiet=a.quiet,
        verbose=a.verbose,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = cfg_from_args(args)
    utils.set_log_levels(cfg.quiet, cfg.verbose)

    utils.info(f"servicescan starting against {cfg.target}")
    try:
        result = asyncio.run(orchestrator.run(cfg))
    except KeyboardInterrupt:
        utils.warn("interrupted")
        return 130

    report.write_all(cfg.outdir, result)
    if not cfg.quiet:
        report.console_summary(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
