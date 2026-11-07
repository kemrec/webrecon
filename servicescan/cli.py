"""Command-line interface for servicescan."""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

from .config import ScanConfig
from . import orchestrator, report, targets
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
  servicescan 10.0.0.5 --web                # scan, then webrecon every web port,
                                            #   pivoting on cert SANs (internal zones)
  servicescan 10.0.0.5 --full               # thorough web chain (render, depth 3)
  servicescan 10.0.0.5 --web --write-hosts  # also persist cert SANs to /etc/hosts
  servicescan 10.0.0.0/24                    # whole CIDR block
  servicescan 10.0.0.1-50                    # nmap-style range
  servicescan 10.0.0.5 10.0.0.6 host.lab     # several targets at once
  servicescan -iL targets.txt --web          # targets from a file, one per line
  NVD_API_KEY=xxxx servicescan host          # raise NVD rate limit
""",
    )
    p.add_argument("target", nargs="*",
                   help="one or more IPs / hostnames / CIDR blocks "
                        "(10.0.0.0/24) / ranges (10.0.0.1-50)")
    p.add_argument("-iL", "--target-file", dest="target_file", default=None,
                   metavar="FILE",
                   help="read targets from FILE (one per line, '#' comments ok)")

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

    wb = p.add_argument_group("web chain")
    wb.add_argument("--web", action="store_true",
                    help="after scanning, run webrecon on every discovered "
                         "HTTP(S) port, pivoting on TLS cert SANs to enumerate "
                         "cert-only / internal virtual hosts against the IP")
    wb.add_argument("--full", action="store_true",
                    help="thorough web-chain profile (implies --web): JS "
                         "rendering on, depth 3, 300 pages per port. Any "
                         "--web-* flag you pass still overrides these.")
    wb.add_argument("--web-render", action="store_true",
                    help="use Playwright JS rendering in the web chain "
                         "(default HTTP-only; on under --full)")
    wb.add_argument("--web-depth", type=int, default=None,
                    help="crawl depth per web port (default 1, or 3 under --full)")
    wb.add_argument("--web-max-pages", type=int, default=None,
                    help="page cap per web port (default 60, or 300 under --full)")
    wb.add_argument("--write-hosts", action="store_true",
                    help="append harvested cert SANs -> IP to /etc/hosts "
                         "(needs root; for use by other tools)")

    net = p.add_argument_group("network")
    net.add_argument("-c", "--concurrency", type=int, default=50)
    net.add_argument("-t", "--timeout", type=float, default=8.0)

    o = p.add_argument_group("output")
    o.add_argument("-o", "--outdir", default="servicescan-out")
    o.add_argument("-q", "--quiet", action="store_true")
    o.add_argument("-v", "--verbose", action="store_true")
    return p


def collect_targets(a: argparse.Namespace) -> list[str]:
    toks: list[str] = []
    for t in (a.target or []):
        toks.extend(t.replace(",", " ").split())
    if a.target_file:
        toks.extend(targets.read_target_file(a.target_file))
    # de-dup, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for t in toks:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def cfg_from_args(a: argparse.Namespace) -> ScanConfig:
    toks = collect_targets(a)
    return ScanConfig(
        target=" ".join(toks),
        targets=toks,
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
        web=a.web or a.full,
        web_render=a.web_render or a.full,
        web_depth=(a.web_depth if a.web_depth is not None else (3 if a.full else 1)),
        web_max_pages=(a.web_max_pages if a.web_max_pages is not None
                       else (300 if a.full else 60)),
        write_hosts=a.write_hosts,
        concurrency=a.concurrency,
        timeout=a.timeout,
        outdir=a.outdir,
        quiet=a.quiet,
        verbose=a.verbose,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = cfg_from_args(args)
    if not cfg.targets:
        parser.error("no targets given (positional target(s) or -iL FILE)")
    utils.set_log_levels(cfg.quiet, cfg.verbose)

    ntxt = (f"{len(cfg.targets)} target spec(s)" if len(cfg.targets) > 1
            else cfg.target)
    utils.info(f"servicescan starting against {ntxt}")
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
