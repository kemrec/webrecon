#!/usr/bin/env python3
"""Build servicescan's compact technology-fingerprint catalog.

Source: projectdiscovery/wappalyzergo `fingerprints_data.json` (MIT licensed,
Copyright (c) 2021 ProjectDiscovery, Inc.), itself derived from the last
open-source Wappalyzer ruleset. We vendor nothing at runtime and depend on no
external tool: this script compiles a SNAPSHOT of that data into our own
compact schema, and only the generated file is shipped.

Refresh:
    git clone --depth 1 https://github.com/projectdiscovery/wappalyzergo /tmp/wg
    python scripts/build_tech_catalog.py /tmp/wg/fingerprints_data.json \
        servicescan/data/tech_fingerprints.json

We keep only apps that carry a CPE (the ones we can CVE-correlate) and reduce
each to the signals we can cheaply match on an HTTP response: response headers,
<meta> generators, <script src> and body HTML. JS-runtime checks are dropped.

Output schema:
    {"_meta": {...},
     "apps": {"<name>": {"cpe": ["vendor","product"],
                          "sigs": [{"loc":"header|meta|script|html|cookie",
                                    "key":"<header/meta/cookie name>"?,
                                    "re":"<regex>", "v":<version group or 0>}]}}}
"""
from __future__ import annotations

import json
import re
import sys
import time


def _parse_cpe(cpe: str):
    """cpe:2.3:a:vendor:product:... -> [vendor, product] or None."""
    parts = cpe.split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        vendor, product = parts[3], parts[4]
        if vendor and product and vendor != "*" and product != "*":
            return [vendor, product]
    return None


def _split_pattern(raw: str):
    """A wappalyzer pattern is 'regex\\;version:\\N\\;confidence:NN'. Return
    (regex, version_group:int). version_group 0 means no version capture."""
    parts = raw.split("\\;")
    regex = parts[0]
    vgroup = 0
    for d in parts[1:]:
        if d.startswith("version:"):
            m = re.search(r"\\(\d+)", d)       # first \N backreference
            if m:
                vgroup = int(m.group(1))
    return regex, vgroup


def _valid(regex: str) -> bool:
    """Keep only regexes Python's engine accepts (JS rules are mostly PCRE)."""
    try:
        re.compile(regex, re.I)
        return True
    except re.error:
        return False


def _emit(sigs, loc, key, raw):
    if raw is None:
        return
    # a dict value may be a single pattern or a list of them
    values = raw if isinstance(raw, list) else [raw]
    for v in values:
        if not isinstance(v, str):
            continue
        regex, vgroup = _split_pattern(v)
        if regex == "":
            regex = ".*"                       # presence-only signal
        if not _valid(regex):
            continue
        sig = {"loc": loc, "re": regex, "v": vgroup}
        if key is not None:
            sig["key"] = key.lower()
        sigs.append(sig)


def build(src_path: str, out_path: str) -> None:
    data = json.load(open(src_path, encoding="utf-8"))
    apps = data["apps"]
    out = {}
    for name, a in apps.items():
        cpe = a.get("cpe")
        if not cpe:
            continue                           # only CVE-correlatable apps
        parsed = _parse_cpe(cpe)
        if not parsed:
            continue
        sigs: list = []
        for key, pat in (a.get("headers") or {}).items():
            _emit(sigs, "header", key, pat)
        for key, pat in (a.get("meta") or {}).items():
            _emit(sigs, "meta", key, pat)
        for key, pat in (a.get("cookies") or {}).items():
            _emit(sigs, "cookie", key, pat)
        for pat in (a.get("scriptSrc") or []):
            _emit(sigs, "script", None, pat)
        for pat in (a.get("html") or []):
            _emit(sigs, "html", None, pat)
        if not sigs:
            continue
        out[name] = {"cpe": parsed, "sigs": sigs}

    payload = {
        "_meta": {
            "source": "projectdiscovery/wappalyzergo (MIT, (c) 2021 "
                      "ProjectDiscovery, Inc.); derived from open-source Wappalyzer",
            "generated": time.strftime("%Y-%m-%d"),
            "apps": len(out),
        },
        "apps": out,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, separators=(",", ":"), ensure_ascii=False)
    nver = sum(1 for a in out.values() if any(s["v"] for s in a["sigs"]))
    print(f"wrote {out_path}: {len(out)} apps ({nver} with version capture)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    build(sys.argv[1], sys.argv[2])
