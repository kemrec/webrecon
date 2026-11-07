"""Output writers: JSON (machine), plaintext lists (greppable), console summary."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from . import utils
from .utils import C


def _w(path: str, lines) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for ln in lines:
            fh.write(str(ln) + "\n")


def write_all(outdir: str, data: dict) -> None:
    os.makedirs(outdir, exist_ok=True)

    # full JSON
    with open(os.path.join(outdir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, default=_json_default)

    # greppable plaintext lists
    _w(os.path.join(outdir, "urls.txt"), sorted(data.get("urls", [])))
    _w(os.path.join(outdir, "js_files.txt"), sorted(data.get("js_files", [])))
    _w(os.path.join(outdir, "endpoints.txt"), sorted(data.get("endpoints", [])))

    params = data.get("params", {})
    plines = []
    for ep in sorted(params):
        plines.append(f"{ep}\t{','.join(sorted(params[ep]))}")
    _w(os.path.join(outdir, "params.txt"), plines)

    _w(os.path.join(outdir, "subdomains.txt"), sorted(data.get("subdomains", [])))

    alive = data.get("alive_urls", []) + data.get("alive_hosts", [])
    alines = [f"{a['status']}\t{a['url']}\t{a.get('title','')}" for a in alive]
    _w(os.path.join(outdir, "alive.txt"), alines)

    vlines = [f"{v['ip']}\t{v['host']}\t{v['status']}\t{v['length']}b"
              for v in data.get("vhosts", [])]
    _w(os.path.join(outdir, "vhosts.txt"), vlines)

    slines = []
    for s in data.get("secrets", []):
        slines.append(f"[{s['severity'].upper()}] {s['type']}\t{s['match_preview']}"
                      f"\t{s['source']}:{s['line']}")
    _w(os.path.join(outdir, "secrets.txt"), slines)

    utils.good(f"output written to {outdir}/ (report.json + *.txt)")


def _json_default(o):
    if isinstance(o, set):
        return sorted(o)
    return str(o)


def console_summary(data: dict) -> None:
    s = data
    sec = s.get("secrets", [])
    high = sum(1 for x in sec if x["severity"] == "high")
    med = sum(1 for x in sec if x["severity"] == "medium")
    low = sum(1 for x in sec if x["severity"] == "low")

    print(f"\n{C.B}{'='*60}{C.R}")
    print(f"{C.B} webrecon summary — {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}{C.R}")
    print(f"{C.B}{'='*60}{C.R}")
    print(f"  {C.CYN}target{C.R}            : {s.get('target','')}")
    print(f"  {C.CYN}pages crawled{C.R}     : {len(s.get('pages', {}))}")
    print(f"  {C.CYN}urls discovered{C.R}   : {len(s.get('urls', []))}")
    print(f"  {C.CYN}js files{C.R}          : {len(s.get('js_files', []))}")
    print(f"  {C.CYN}endpoints (raw){C.R}   : {len(s.get('endpoints', []))}")
    print(f"  {C.CYN}params'd endpoints{C.R}: {len(s.get('params', {}))}")
    print(f"  {C.CYN}subdomains{C.R}        : {len(s.get('subdomains', []))}")
    print(f"  {C.CYN}vhosts found{C.R}      : {len(s.get('vhosts', []))}")
    print(f"  {C.CYN}alive urls{C.R}        : {len(s.get('alive_urls', []))}")
    print(f"  {C.CYN}alive hosts{C.R}       : {len(s.get('alive_hosts', []))}")
    sev_col = C.RED if high else (C.YEL if med else C.GRN)
    print(f"  {sev_col}secrets{C.R}           : {len(sec)} "
          f"({C.RED}{high} high{C.R}, {C.YEL}{med} med{C.R}, {low} low)")
    print(f"{C.B}{'='*60}{C.R}")

    if sec:
        print(f"{C.MAG}{C.B}  Top secret findings:{C.R}")
        for x in sorted(sec, key=lambda d: {"high":0,"medium":1,"low":2}[d["severity"]])[:12]:
            col = C.RED if x["severity"] == "high" else (C.YEL if x["severity"] == "medium" else C.GRY)
            print(f"   {col}[{x['severity'][:1].upper()}]{C.R} {x['type']}: "
                  f"{x['match_preview']}  {C.GRY}({x['source']}:{x['line']}){C.R}")
        print()
