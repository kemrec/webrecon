"""Output writers for servicescan: JSON, txt, colored console summary."""
from __future__ import annotations

import json
import os

from webrecon import utils
from webrecon.utils import C
from .models import ScanResult


def _sev_color(sev: str, score) -> str:
    s = (sev or "").upper()
    if s == "CRITICAL" or (score or 0) >= 9:
        return C.RED + C.B
    if s == "HIGH" or (score or 0) >= 7:
        return C.RED
    if s == "MEDIUM" or (score or 0) >= 4:
        return C.YEL
    return C.GRY


def write_all(outdir: str, result: ScanResult) -> None:
    os.makedirs(outdir, exist_ok=True)
    data = result.to_dict()

    with open(os.path.join(outdir, "scan.json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)

    # services.txt  (host-prefixed)
    slines = []
    for h in result.hosts:
        hid = h.ip or h.hostname or h.target
        for s in h.services:
            ident = s.ident()
            src = "+".join(s.sources)
            slines.append(f"{hid}\t{s.port}/{s.proto}\t{s.state}\t{s.name}\t{ident}"
                          f"\t[{s.confidence}]\t({src})")
    _w(os.path.join(outdir, "services.txt"), slines)

    # cves.txt  (flat, sorted by score desc, host-prefixed)
    clines = []
    flat = []
    for h in result.hosts:
        hid = h.ip or h.hostname or h.target
        for s in h.services:
            for c in s.cves:
                flat.append((hid, s, c))
    flat.sort(key=lambda hsc: -(hsc[2].cvss or 0))
    for hid, s, c in flat:
        score = f"{c.cvss:.1f}" if c.cvss is not None else "  ?"
        epss = f"{c.epss*100:.1f}%" if c.epss is not None else "-"
        kev = "KEV" if c.kev else "-"
        clines.append(f"{score}\t{c.severity or '?':8}\t{c.id}\t"
                      f"{hid}\t{s.port}/{s.ident()}\tepss={epss}\t{kev}"
                      f"\t{c.source}\t{c.url}")
    _w(os.path.join(outdir, "cves.txt"), clines)

    utils.good(f"output written to {outdir}/ (scan.json + services.txt + cves.txt)")


def _w(path: str, lines) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for ln in lines:
            fh.write(str(ln) + "\n")


def console_summary(result: ScanResult) -> None:
    live_hosts = [h for h in result.hosts if h.services]
    all_svcs = result.services

    print(f"\n{C.B}{'='*66}{C.R}")
    print(f"{C.B} servicescan — {result.target}{C.R}")
    print(f"{C.B}{'='*66}{C.R}")
    if not result.nmap_used:
        print(f"  {C.YEL}note{C.R}: nmap not used (fallback mode — limited coverage)")

    total_cve = sum(len(s.cves) for s in all_svcs)
    crit = sum(1 for s in all_svcs for c in s.cves if (c.cvss or 0) >= 9)
    high = sum(1 for s in all_svcs for c in s.cves if 7 <= (c.cvss or 0) < 9)
    kev = sum(1 for s in all_svcs for c in s.cves if c.kev)
    print(f"  hosts up      : {len(live_hosts)}")
    print(f"  open services : {len(all_svcs)}")
    print(f"  CVEs found    : {total_cve}  "
          f"({C.RED}{crit} critical{C.R}, {C.RED}{high} high{C.R}, "
          f"{C.RED}{C.B}{kev} KEV{C.R})")

    for h in live_hosts:
        print(f"{C.B}{'-'*66}{C.R}")
        print(f"  {C.B}{C.CYN}{h.label()}{C.R}  {C.GRY}"
              f"({len(h.services)} open){C.R}")
        for s in h.services:
            _print_service(s)
    print(f"{C.B}{'='*66}{C.R}")


def _print_service(s) -> None:
    ver_col = C.GRN if s.version else C.YEL
    src = "+".join(s.sources)
    print(f"  {C.CYN}{s.port}/{s.proto}{C.R}  {s.name or '?':10} "
          f"{ver_col}{s.ident():30}{C.R} {C.GRY}[{s.confidence}|{src}]{C.R}")
    if s.http.get("title"):
        print(f"        {C.GRY}title: {s.http['title']}{C.R}")
    for c in s.cves[:6]:
        col = _sev_color(c.severity, c.cvss)
        score = f"{c.cvss:.1f}" if c.cvss is not None else "?"
        kev = f"  {C.RED}{C.B}[KEV]{C.R}" if c.kev else ""
        epss = (f"  {C.GRY}EPSS {c.epss*100:.1f}%{C.R}"
                if c.epss is not None else "")
        print(f"        {col}{c.id}  CVSS {score}  {c.severity}{C.R}{kev}{epss}  "
              f"{C.GRY}{c.summary[:60]}{C.R}")
    if len(s.cves) > 6:
        print(f"        {C.GRY}... +{len(s.cves)-6} more (see cves.txt){C.R}")
    if s.web:
        w = s.web
        vh = w.get("vhosts", [])
        print(f"        {C.CYN}web{C.R}: {w.get('pages',0)}p "
              f"{w.get('urls',0)}url {w.get('endpoints',0)}ep "
              f"{w.get('secrets',0)}secret {len(vh)}vhost  "
              f"{C.GRY}-> {w.get('outdir','')}{C.R}")
        for v in vh[:5]:
            print(f"           {C.GRN}vhost{C.R} {v.get('host')} "
                  f"-> {v.get('status')} ({v.get('length')}b)")
