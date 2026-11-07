"""CVE correlation from NVD and OSV.

Given a Service's (product, version) — and any CPEs nmap already produced —
query:
  * NVD 2.0 REST API   : https://services.nvd.nist.gov/rest/json/cves/2.0
      - best by cpeName (exact CPE 2.3), else keyword search
  * OSV.dev            : https://api.osv.dev/v1/query
      - best for open-source packages/libraries by (name, version)

Results are normalized into CVE models with CVSS base score + severity.
Network failures are swallowed (recon is best-effort); the structure still
returns so the scan completes.
"""
from __future__ import annotations

import asyncio

from .config import ScanConfig
from .models import Service, CVE
from webrecon import utils


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1/query"


# ---------------------------------------------------------------------------
# product-name normalization: our labels -> likely NVD vendor/product + OSV name
# ---------------------------------------------------------------------------
_CPE_MAP = {
    # product (lowercased) : (cpe_vendor, cpe_product)
    "openssh": ("openbsd", "openssh"),
    "apache httpd": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "redis": ("redis", "redis"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "grafana": ("grafana", "grafana"),
    "openssl": ("openssl", "openssl"),
    "php": ("php", "php"),
    "tomcat": ("apache", "tomcat"),
    "jenkins": ("jenkins", "jenkins"),
}

# OSV ecosystem names (open-source packages OSV tracks well)
_OSV_NAME = {
    "wordpress": "WordPress",
    "grafana": "grafana",
    "nginx": "nginx",
}


def make_cpe(product: str, version: str) -> str | None:
    """Build a CPE 2.3 string from product/version if we know the mapping."""
    key = product.strip().lower()
    mapping = _CPE_MAP.get(key)
    if not mapping:
        return None
    vendor, prod = mapping
    ver = version.strip() or "*"
    return f"cpe:2.3:a:{vendor}:{prod}:{ver}:*:*:*:*:*:*:*"


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------
def _nvd_severity_cvss(cve_obj: dict) -> tuple[float | None, str]:
    metrics = cve_obj.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            score = data.get("baseScore")
            sev = (arr[0].get("baseSeverity")
                   or data.get("baseSeverity", "")).upper()
            if score is not None and not sev:
                sev = _score_to_sev(score)
            return score, sev
    return None, ""


def _score_to_sev(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def parse_nvd(payload: dict) -> list[CVE]:
    out: list[CVE] = []
    for item in payload.get("vulnerabilities", []):
        c = item.get("cve", {})
        cid = c.get("id", "")
        if not cid:
            continue
        descs = c.get("descriptions", [])
        summary = ""
        for d in descs:
            if d.get("lang") == "en":
                summary = d.get("value", "")
                break
        score, sev = _nvd_severity_cvss(c)
        out.append(CVE(
            id=cid, source="nvd", cvss=score, severity=sev,
            summary=summary[:300],
            url=f"https://nvd.nist.gov/vuln/detail/{cid}",
            published=c.get("published", "")[:10],
        ))
    return out


async def query_nvd(http, cfg: ScanConfig, cpe: str | None,
                    keyword: str | None) -> list[CVE]:
    params = {"resultsPerPage": str(min(cfg.max_cves_per_service, 100))}
    if cpe:
        params["cpeName"] = cpe
        params["isVulnerable"] = ""        # only CVEs applicable to this CPE
    elif keyword:
        params["keywordSearch"] = keyword
    else:
        return []
    qs = "&".join(f"{k}={v}" for k, v in params.items() if v != "" or k == "isVulnerable")
    url = f"{NVD_URL}?{qs}"
    headers = {"apiKey": cfg.nvd_api_key} if cfg.nvd_api_key else None
    r = await http.fetch(url, method="GET", headers=headers, read_body=True)
    if not r.ok or r.status != 200:
        utils.debug(f"nvd {r.status} for {cpe or keyword}")
        return []
    import json
    try:
        return parse_nvd(json.loads(r.text))
    except Exception as e:  # noqa: BLE001
        utils.debug(f"nvd parse: {e}")
        return []


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------
def parse_osv(payload: dict) -> list[CVE]:
    out: list[CVE] = []
    for v in payload.get("vulns", []):
        vid = v.get("id", "")
        aliases = v.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vid)
        summary = v.get("summary") or v.get("details", "")
        score = None
        sev = ""
        for s in v.get("severity", []):
            if s.get("type", "").startswith("CVSS"):
                # OSV gives vector strings; try to pull a base score if numeric
                val = s.get("score", "")
                try:
                    score = float(val)
                    sev = _score_to_sev(score)
                except (TypeError, ValueError):
                    pass
        out.append(CVE(
            id=cve_id, source="osv", cvss=score, severity=sev,
            summary=(summary or "")[:300],
            url=f"https://osv.dev/vulnerability/{vid}",
            published=v.get("published", "")[:10],
        ))
    return out


# OSV uses a POST body; webrecon's HTTPClient is GET/HEAD-oriented, so the
# correlate() step below talks to OSV with a direct httpx POST.


# ---------------------------------------------------------------------------
# Correlation entry point
# ---------------------------------------------------------------------------
async def correlate(cfg: ScanConfig, http, services: list[Service]) -> None:
    """Attach CVEs to each service that has an identifiable product."""
    import httpx

    async def osv_direct(name: str, version: str) -> list[CVE]:
        try:
            async with httpx.AsyncClient(timeout=cfg.timeout, verify=False) as cl:
                resp = await cl.post(OSV_URL,
                                     json={"package": {"name": name},
                                           "version": version})
            if resp.status_code == 200:
                return parse_osv(resp.json())
        except Exception as e:  # noqa: BLE001
            utils.debug(f"osv {name} {version}: {type(e).__name__}")
        return []

    sem = asyncio.Semaphore(max(4, cfg.concurrency // 4))  # APIs are rate-limited

    async def one(svc: Service):
        if not svc.product:
            return
        async with sem:
            found: dict[str, CVE] = {}
            # --- NVD ---
            if cfg.nvd:
                cpe = (svc.cpe[0] if svc.cpe else None) or make_cpe(
                    svc.product, svc.version)
                kw = None if cpe else f"{svc.product} {svc.version}".strip()
                for c in await query_nvd(http, cfg, cpe, kw):
                    found.setdefault(c.id, c)
                if cpe:
                    utils.debug(f":{svc.port} nvd via {cpe}")
            # --- OSV (open-source packages) ---
            if cfg.osv and svc.version:
                osv_name = _OSV_NAME.get(svc.product.lower())
                if osv_name:
                    for c in await osv_direct(osv_name, svc.version):
                        found.setdefault(c.id, c)

            cves = [c for c in found.values()
                    if (c.cvss is None or c.cvss >= cfg.min_cvss)]
            cves.sort(key=lambda c: (-(c.cvss or 0), c.id))
            svc.cves = cves[: cfg.max_cves_per_service]
            if svc.cves:
                crit = sum(1 for c in svc.cves if (c.cvss or 0) >= 9)
                utils.hit(f":{svc.port} {svc.ident()} -> {len(svc.cves)} CVEs "
                          f"({crit} critical)")

    await asyncio.gather(*(one(s) for s in services))
