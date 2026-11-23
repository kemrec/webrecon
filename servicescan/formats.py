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
                    "eff_cvss", "eff_severity", "env_note",
                    "epss", "kev", "exploits", "source", "url"])
        for hid, _hn, s in _rows(result):
            for c in s.cves:
                w.writerow([hid, s.port, s.ident(), c.id,
                            "" if c.cvss is None else c.cvss, c.severity,
                            "" if c.effective_cvss is None else c.effective_cvss,
                            c.effective_severity, c.env_note,
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
                   "extrainfo": s.extrainfo, "http": s.http,
                   "scripts": s.scripts,
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
.svc .stitle{display:block;color:#9aa0a6;font-weight:400;font-size:12px}
.badge{display:inline-block;padding:1px 6px;border-radius:5px;font-size:11px;font-weight:700;margin-left:4px}
.kev{background:#b11;color:#fff}.exp{background:#a60;color:#fff}
.crit{color:#ff6b6b;font-weight:700}.high{color:#ff9f43}.med{color:#ffd93d}.low{color:#9aa0a6}
a{color:#7fd1ff;text-decoration:none} a:hover{text-decoration:underline}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
"""


def _sev_class(sev, score):
    # a textual severity is authoritative (an environmentally demoted CVE keeps
    # its canonical score but must render in its demoted class); the numeric
    # band is only the fallback when no severity label is present.
    s = (sev or "").upper()
    if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
        return {"CRITICAL": "crit", "HIGH": "high",
                "MEDIUM": "med"}.get(s, "low")
    if (score or 0) >= 9:
        return "crit"
    if (score or 0) >= 7:
        return "high"
    if (score or 0) >= 4:
        return "med"
    return "low"


def write_html(outdir: str, result) -> None:
    e = html.escape
    svcs = result.services
    total_cve = sum(len(s.cves) for s in svcs)
    crit = sum(1 for s in svcs for c in s.cves if (c.disp_cvss() or 0) >= 9)
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
            # the fingerprinted HTTP page <title>, shown under the service name
            title = (s.http or {}).get("title", "")
            svc_cell = (f"<td class='svc'>{e(s.name)}"
                        + (f"<span class='stitle'>{e(title)}</span>" if title else "")
                        + "</td>")
            if not s.cves:
                parts.append(f"<tr><td class='mono'>{s.port}/{s.proto}</td>"
                             f"{svc_cell}<td colspan='5'>"
                             f"{ident}</td></tr>")
                continue
            for i, c in enumerate(s.cves):
                portcell = (f"<td class='mono'>{s.port}/{s.proto}</td>"
                            f"{svc_cell}") if i == 0 else \
                           "<td></td><td></td>"
                cls = _sev_class(c.disp_severity(), c.disp_cvss())
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
                    f"<td>{flags}</td><td>{e(c.disp_summary()[:160])}</td></tr>")
        parts.append("</table></div>")

    parts.append("</div></body></html>")
    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write("".join(parts))


# ---------------------------------------------------------------------------
# SARIF 2.1.0 (static-analysis results interchange format) -- for CI / GitHub
# code-scanning ingestion. Two kinds of result: a CVE on a service, and an
# unauthenticated-exposure alert (the critical scripts). Locations use a
# host:port locator (there is no source file); GitHub reads rule severity from
# properties["security-severity"].
# ---------------------------------------------------------------------------
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/kemrec/webrecon"


def _sarif_level(sev, score) -> str:
    s = (sev or "").upper()
    if s in ("CRITICAL", "HIGH") or (score or 0) >= 7:
        return "error"
    if s == "MEDIUM" or (score or 0) >= 4:
        return "warning"
    return "note"


def _sarif_sec_sev(score, sev) -> str:
    if score is not None:
        return f"{score:.1f}"
    return {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5",
            "LOW": "3.0"}.get((sev or "").upper(), "")


def _sarif_results(result):
    """Yield (rule_dict, result_dict) for every CVE and exposure-alert finding."""
    from .fingerprint import EXPOSURE_ALERT_IDS
    alert_ids = {"bindshell-detect"} | EXPOSURE_ALERT_IDS

    for hid, _hn, s in _rows(result):
        loc_uri = f"{hid}:{s.port}/{s.proto}"
        svc_props = {"host": hid, "port": s.port, "proto": s.proto,
                     "service": s.name or "", "product": s.product or "",
                     "version": s.version or ""}

        def _result(rule_id, level, text, extra=None):
            props = dict(svc_props)
            if extra:
                props.update(extra)
            return {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": text},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": loc_uri}}}],
                "partialFingerprints": {
                    "servicescan/v1": f"{hid}:{s.port}:{rule_id}"},
                "properties": props,
            }

        for c in s.cves:
            score = c.disp_cvss()
            sev = c.disp_severity()
            rule = {
                "id": c.id,
                "name": c.id.replace("-", "_"),
                "shortDescription": {"text": (c.disp_summary() or c.id)[:200]},
                "helpUri": c.url or _INFO_URI,
                "properties": {"tags": ["security", "cve"],
                               "security-severity": _sarif_sec_sev(score, sev)},
            }
            score_s = f"{score:.1f}" if score is not None else "?"
            prod = (f"{s.product} {s.version}".strip() or s.ident())
            text = (f"{c.id} ({sev or 'unknown'}, CVSS {score_s}) affects "
                    f"{prod} on {loc_uri}."
                    + (f" {c.disp_summary()}" if c.disp_summary() else "")
                    + (" [CISA KEV]" if c.kev else ""))
            yield rule, _result(c.id, _sarif_level(sev, score), text,
                                {"cvss": score, "kev": bool(c.kev),
                                 "epss": c.epss})

        for sc in getattr(s, "scripts", []):
            sid = sc.get("id", "")
            if sid not in alert_ids:
                continue
            rule = {
                "id": sid,
                "name": sid.replace("-", "_"),
                "shortDescription": {
                    "text": f"Unauthenticated exposure: {sid}"},
                "helpUri": _INFO_URI,
                "properties": {"tags": ["security", "exposure"],
                               "security-severity": "9.0"},
            }
            yield rule, _result(sid, "error", sc.get("output", sid))


def build_sarif(result) -> dict:
    """Build the SARIF 2.1.0 document in memory (no filesystem).

    Shared by write_sarif() and the web UI's SARIF download endpoint so both
    emit byte-identical reports.
    """
    rules: dict = {}
    results = []
    for rule, res in _sarif_results(result):
        rules.setdefault(rule["id"], rule)        # one rule object per ruleId
        results.append(res)

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "servicescan",
                "informationUri": _INFO_URI,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def write_sarif(outdir: str, result) -> None:
    doc = build_sarif(result)
    with open(os.path.join(outdir, "scan.sarif"), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)


def write_extra(outdir: str, result) -> None:
    write_csv(outdir, result)
    write_jsonl(outdir, result)
    write_html(outdir, result)
    write_sarif(outdir, result)
