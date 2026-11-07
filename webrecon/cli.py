"""Command-line interface for webrecon."""
from __future__ import annotations

import argparse
import asyncio
import sys

from .config import Config, DEFAULT_UA
from . import utils, orchestrator, report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webrecon",
        description="Full-featured async web crawler & recon toolkit "
                    "(crawl + JS endpoints + params + alive + subdomains + "
                    "vhost + secret scanning).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  webrecon https://example.com
  webrecon example.com -d 3 --max-pages 500 -c 60
  webrecon https://example.com --no-render           # fast HTTP-only crawl
  webrecon example.com --only secrets,js             # just JS mining + secrets
  webrecon example.com --vhost-wordlist hosts.txt -o out/
""",
    )
    p.add_argument("target", help="target URL or host (scheme optional)")

    # crawl options
    g = p.add_argument_group("crawl")
    g.add_argument("-d", "--depth", type=int, default=2, help="crawl depth (default 2)")
    g.add_argument("--max-pages", type=int, default=300, help="max pages (default 300)")
    g.add_argument("--no-render", action="store_true",
                   help="disable Playwright JS rendering (HTTP-only, faster)")
    g.add_argument("--headful", action="store_true", help="run browser headed (debug)")
    g.add_argument("--wait-until", default="networkidle",
                   choices=["load", "domcontentloaded", "networkidle", "commit"],
                   help="playwright navigation wait (default networkidle)")
    g.add_argument("--page-timeout", type=int, default=20000,
                   help="per-page render timeout ms (default 20000)")
    g.add_argument("--no-subs-scope", action="store_true",
                   help="do NOT treat subdomains as in-scope for crawling")

    # networking
    n = p.add_argument_group("network")
    n.add_argument("-c", "--concurrency", type=int, default=40,
                   help="async concurrency (default 40)")
    n.add_argument("-t", "--timeout", type=float, default=12.0,
                   help="per-request timeout s (default 12)")
    n.add_argument("--retries", type=int, default=1)
    n.add_argument("-A", "--user-agent", default=DEFAULT_UA)
    n.add_argument("-H", "--header", action="append", default=[],
                   metavar="K:V", help="extra header (repeatable)")
    n.add_argument("--proxy", default=None, help="http(s) proxy url")
    n.add_argument("--verify-tls", action="store_true",
                   help="verify TLS certs (default: off for recon)")

    # discovery
    dsc = p.add_argument_group("discovery")
    dsc.add_argument("--subdomain-wordlist", default=None)
    dsc.add_argument("--vhost-wordlist", default=None)

    # phase selection
    sel = p.add_argument_group("phases")
    sel.add_argument("--only", default=None,
                     help="comma list of phases to RUN: "
                          "crawl,js,secrets,subs,vhost,alive")
    sel.add_argument("--skip", default=None,
                     help="comma list of phases to SKIP (same names)")

    # output
    o = p.add_argument_group("output")
    o.add_argument("-o", "--outdir", default="webrecon-out",
                   help="output directory (default webrecon-out)")
    o.add_argument("-q", "--quiet", action="store_true", help="suppress progress logs")
    o.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return p


_PHASE_ATTR = {
    "crawl": "do_crawl", "js": "do_js_extract", "secrets": "do_secrets",
    "subs": "do_subdomains", "vhost": "do_vhost", "alive": "do_alive",
}


def cfg_from_args(a: argparse.Namespace) -> Config:
    headers = {}
    for h in a.header:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()

    cfg = Config(
        target=utils.ensure_scheme(a.target),
        depth=a.depth,
        max_pages=a.max_pages,
        render=not a.no_render,
        headful=a.headful,
        wait_until=a.wait_until,
        page_timeout=a.page_timeout,
        include_subdomains=not a.no_subs_scope,
        concurrency=a.concurrency,
        timeout=a.timeout,
        retries=a.retries,
        user_agent=a.user_agent,
        extra_headers=headers,
        proxy=a.proxy,
        verify_tls=a.verify_tls,
        subdomain_wordlist=a.subdomain_wordlist,
        vhost_wordlist=a.vhost_wordlist,
        outdir=a.outdir,
        quiet=a.quiet,
        verbose=a.verbose,
    )
    cfg.scope_hosts = {utils.host_of(cfg.target)}

    # phase selection
    if a.only:
        wanted = {x.strip() for x in a.only.split(",") if x.strip()}
        for name, attr in _PHASE_ATTR.items():
            setattr(cfg, attr, name in wanted)
    if a.skip:
        for x in a.skip.split(","):
            x = x.strip()
            if x in _PHASE_ATTR:
                setattr(cfg, _PHASE_ATTR[x], False)
    return cfg


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = cfg_from_args(args)
    utils.set_log_levels(cfg.quiet, cfg.verbose)

    if not utils.host_of(cfg.target):
        utils.err(f"invalid target: {args.target}")
        return 2

    utils.info(f"webrecon starting against {cfg.target}")
    try:
        data = asyncio.run(orchestrator.run(cfg))
    except KeyboardInterrupt:
        utils.warn("interrupted by user")
        return 130

    report.write_all(cfg.outdir, data)
    if not cfg.quiet:
        report.console_summary(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
