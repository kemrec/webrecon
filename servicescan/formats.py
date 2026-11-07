"""Extra output writers for servicescan: CSV, JSONL, and a standalone HTML report.

All are generated alongside scan.json/services.txt/cves.txt and need no external
libraries. The HTML report is a single self-contained file (inline CSS) that
renders host -> service -> CVE with CVSS/EPSS/KEV/exploit badges.
"""
from __future__ import annotations

import csv
import html
import json
import os


def _rows(result):
    """Yield (host_id, hostname, Service) across all hosts."""
    for h in result.hosts:
        hid = h.ip or h.hostname or h.target
        for s in h.services:
            yield hid, h.hostname, s


def write_csv(outdir: str, result) -> None:
    with open(os.path.join(outdir, "services.csv"), "w", newline="",
              encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "hostname", "port", "proto", "state", "name",
                    "product", "version", "confidence", "sources"])
        for hid, hn, s in _rows(result):
            w.writerow([hid, hn, s.port, s.proto, s.state, s.name, s.product,
                        s.version, s.confidence, "+".join(s.sources)])

    with open(os.path.join(outdir, "cves.csv"), "w", newline="",
              encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "port", "service", "cve", "cvss", "severity",
                    "epss", "kev", "exploits", "source", "url"])
        for hid, _hn, s in _rows(result):
            for c in s.cves:
                w.writerow([hid, s.port, s.ident(), c.id,
                            "" if c.cvss is None else c.cvss, c.severity,
                            "" if c.epss is None else c.epss,
                            int(bool(c.kev)), len(getattr(c, "exploits", []) or []),
                            c.source, c.url])


def write_jsonl(outdir: str, result) -> None:
    """One JSON object per service (host embedded) — easy to grep / ingest."""
    with open(os.path.join(outdir, "scan.jsonl"), "w", encoding="utf-8") as fh:
        for hid, hn, s in _rows(result):
            obj = {"host": hid, "hostname": hn, "port": s.port,
                   "proto": s.proto, "name": s.name, "product": s.product,
                   "version": s.version, "confidence": s.confidence,
                   "cves": [c.to_dict() for c in s.cves]}
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
_CSS = """
body{font:14px/1.5 system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:20px;margin:0 0 4px} .sub{color:#9aa0a6;margin:0 0 20px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.card{background:#1a1d24;border:1px solid #2a2e37;border-radius:10px;padding:12px 16px;min-width:120px}
.card .n{font-size:22px;font-weight:700} .card .l{color:#9aa0a6;font-size:12px}
.host{background:#1a1d24;border:1px solid #2a2e37;border-radius:10px;margin:14px 0;overflow:hidden}
.host h2{font-size:15px;margin:0;padding:10px 14px;background:#20242d;border-bottom:1px solid #2a2e37}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #23272f;vertical-align:top}
th{color:#9aa0a6;font-weight:600;font-size:12px}
.svc{font-weight:600;color:#7fd1ff}
.badge{display:inline-block;padding:1px 6px;border-radius:5px;font-size:11px;font-weight:700;margin-left:4px}
.kev{background:#b11;color:#fff}.exp{background:#a60;color:#fff}
.crit{color:#ff6b6b;font-weight:700}.high{color:#ff9f43}.med{color:#ffd93d}.low{color:#9aa0a6}
a{color:#7fd1ff;text-decoration:none} a:hover{text-decoration:underline}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
"""


def _sev_class(sev, score):
    s = (sev or "").upper()
    if s == "CRITICAL" or (score or 0) >= 9:
        return "crit"
    if s == "HIGH" or (score or 0) >= 7:
        return "high"
    if s == "MEDIUM" or (score or 0) >= 4:
        return "med"
    return "low"


def write_html(outdir: str, result) -> None:
    e = html.escape
    svcs = result.services
    total_cve = sum(len(s.cves) for s in svcs)
    crit = sum(1 for s in svcs for c in s.cves if (c.cvss or 0) >= 9)
    kev = sum(1 for s in svcs for c in s.cves if c.kev)
    exp = sum(1 for s in svcs for c in s.cves if getattr(c, "exploits", None))
    live = [h for h in result.hosts if h.services]

    parts = ['<!doctype html><html><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             f"<title>servicescan — {e(result.target)}</title>",
             f"<style>{_CSS}</style></head><body><div class='wrap'>",
             f"<h1>servicescan report</h1><p class='sub mono'>{e(result.target)}</p>",
             "<div class='cards'>",
             f"<div class='card'><div class='n'>{len(live)}</div><div class='l'>hosts</div></div>",
             f"<div class='card'><div class='n'>{len(svcs)}</div><div class='l'>services</div></div>",
             f"<div class='card'><div class='n'>{total_cve}</div><div class='l'>CVEs</div></div>",
             f"<div class='card'><div class='n crit'>{crit}</div><div class='l'>critical</div></div>",
             f"<div class='card'><div class='n'>{kev}</div><div class='l'>KEV</div></div>",
             f"<div class='card'><div class='n'>{exp}</div><div class='l'>with exploit</div></div>",
             "</div>"]

    for h in live:
        parts.append(f"<div class='host'><h2 class='mono'>{e(h.label())}</h2>")
        parts.append("<table><tr><th>port</th><th>service</th><th>CVE</th>"
                     "<th>CVSS</th><th>EPSS</th><th>flags</th><th>summary</th></tr>")
        for s in h.services:
            ident = e(s.ident())
            if not s.cves:
                parts.append(f"<tr><td class='mono'>{s.port}/{s.proto}</td>"
                             f"<td class='svc'>{e(s.name)}</td><td colspan='5'>"
                             f"{ident}</td></tr>")
                continue
            for i, c in enumerate(s.cves):
                portcell = (f"<td class='mono'>{s.port}/{s.proto}</td>"
                            f"<td class='svc'>{e(s.name)}</td>") if i == 0 else \
                           "<td></td><td></td>"
                cls = _sev_class(c.severity, c.cvss)
                score = "" if c.cvss is None else f"{c.cvss:.1f}"
                epss = "" if c.epss is None else f"{c.epss*100:.1f}%"
                flags = ""
                if c.kev:
                    flags += "<span class='badge kev'>KEV</span>"
                ex = getattr(c, "exploits", None) or []
                if ex:
                    link = e(ex[0].get("url", ""))
                    flags += (f"<span class='badge exp'><a href='{link}' "
                              f"target='_blank'>EXPLOIT x{len(ex)}</a></span>")
                parts.append(
                    f"<tr>{portcell}"
                    f"<td class='mono'><a href='{e(c.url)}' target='_blank'>{e(c.id)}</a></td>"
                    f"<td class='{cls}'>{score}</td><td>{epss}</td>"
                    f"<td>{flags}</td><td>{e(c.summary[:120])}</td></tr>")
        parts.append("</table></div>")

    parts.append("</div></body></html>")
    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write("".join(parts))


def write_extra(outdir: str, result) -> None:
    write_csv(outdir, result)
    write_jsonl(outdir, result)
    write_html(outdir, result)
