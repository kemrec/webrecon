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
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


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


def cpe22_to_23(cpe: str | None) -> str | None:
    """Convert a CPE 2.2 URI (``cpe:/a:vendor:product:version``) to the CPE 2.3
    formatted string NVD's 2.0 API ``cpeName`` parameter requires
    (``cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*``).

    nmap emits CPE 2.2 URIs; feeding those to NVD verbatim 404s, so every
    nmap-identified service would otherwise silently return zero CVEs.
    Strings already in 2.3 form (or an unrecognized shape) are returned as-is.
    """
    if not cpe:
        return None
    cpe = cpe.strip()
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if cpe.startswith("cpe:/"):
        # 2.2 components: part:vendor:product:version:update:edition:language
        fields = cpe[len("cpe:/"):].split(":")
        fields = [f if f else "*" for f in fields]
        fields = (fields + ["*"] * 7)[:7]       # pad/trim to the 7 2.2 fields
        fields += ["*"] * 4                       # extend to the 11 2.3 fields
        return "cpe:2.3:" + ":".join(fields)
    return cpe


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
# EPSS (FIRST.org) + CISA KEV enrichment
# ---------------------------------------------------------------------------
async def epss_lookup(http, cfg, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """Map CVE-ID -> (epss_probability, percentile) via the FIRST.org EPSS API.

    EPSS estimates the probability a CVE is exploited in the wild in the next
    30 days. The API takes a comma-separated ``cve=`` list; we batch to stay
    within URL limits.
    """
    import json
    out: dict[str, tuple[float, float]] = {}
    ids = [c for c in cve_ids if c.startswith("CVE-")]
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        url = f"{EPSS_URL}?cve={','.join(chunk)}"
        r = await http.fetch(url, method="GET", read_body=True)
        if not r.ok or r.status != 200:
            utils.debug(f"epss {r.status} for batch of {len(chunk)}")
            continue
        try:
            data = json.loads(r.text)
        except Exception as e:  # noqa: BLE001
            utils.debug(f"epss parse: {e}")
            continue
        for row in data.get("data", []):
            cid = row.get("cve")
            if not cid:
                continue
            try:
                out[cid] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, TypeError, ValueError):
                pass
    return out


async def kev_lookup(http, cfg) -> set[str]:
    """Return the set of CVE-IDs in the CISA Known Exploited Vulnerabilities
    catalog (fetched once per run)."""
    import json
    r = await http.fetch(KEV_URL, method="GET", read_body=True)
    if not r.ok or r.status != 200:
        utils.debug(f"kev {r.status}")
        return set()
    try:
        data = json.loads(r.text)
    except Exception as e:  # noqa: BLE001
        utils.debug(f"kev parse: {e}")
        return set()
    return {v.get("cveID") for v in data.get("vulnerabilities", [])
            if v.get("cveID")}


async def enrich(cfg, http, services: list[Service]) -> None:
    """Attach EPSS scores and CISA-KEV flags to every CVE already found, then
    re-rank each service's list so known-exploited / high-risk CVEs surface."""
    all_ids = sorted({c.id for s in services for c in s.cves
                      if c.id.startswith("CVE-")})
    if not all_ids:
        return

    epss_map: dict[str, tuple[float, float]] = {}
    kev_set: set[str] = set()
    if cfg.epss:
        epss_map = await epss_lookup(http, cfg, all_ids)
    if cfg.kev:
        kev_set = await kev_lookup(http, cfg)
    if not epss_map and not kev_set:
        return

    for svc in services:
        for c in svc.cves:
            if c.id in epss_map:
                c.epss, c.epss_pct = epss_map[c.id]
            if c.id in kev_set:
                c.kev = True
        # KEV first, then CVSS desc, then EPSS desc.
        svc.cves.sort(key=lambda c: (not c.kev, -(c.cvss or 0),
                                     -(c.epss or 0), c.id))

    n_kev = sum(1 for s in services for c in s.cves if c.kev)
    if n_kev:
        utils.hit(f"{n_kev} CVE(s) listed in CISA KEV (known exploited in the wild)")


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
                # Prefer a clean 2.3 CPE from our own map (carries the version);
                # otherwise convert whatever nmap gave us (CPE 2.2 URI) to 2.3.
                raw_cpe = svc.cpe[0] if svc.cpe else None
                cpe = make_cpe(svc.product, svc.version) or cpe22_to_23(raw_cpe)
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

    # --- enrichment: EPSS probabilities + CISA KEV flags across all findings ---
    if cfg.epss or cfg.kev:
        await enrich(cfg, http, services)
