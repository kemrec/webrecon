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
import re

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
    "vsftpd": ("vsftpd_project", "vsftpd"),   # NVD renames the vendor to
                                              # <product>_project for this one
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
# CPE version-range matching (reduce false positives on keyword search)
# ---------------------------------------------------------------------------
def _vcmp(a: str, b: str) -> int:
    """Compare two version strings: -1 if a<b, 0 if equal, 1 if a>b."""
    try:
        from packaging.version import Version
        va, vb = Version(a), Version(b)
        return (va > vb) - (va < vb)
    except Exception:  # noqa: BLE001
        ta = tuple(int(x) for x in re.findall(r"\d+", a)) or (0,)
        tb = tuple(int(x) for x in re.findall(r"\d+", b)) or (0,)
        return (ta > tb) - (ta < tb)


def _match_cpe(m: dict, want_version: str) -> bool:
    """Does one NVD cpeMatch node apply to our detected version?"""
    crit = m.get("criteria", "")
    fields = crit.split(":")
    cpe_ver = fields[5] if len(fields) > 5 else "*"
    if cpe_ver not in ("*", "-", ""):
        return _vcmp(cpe_ver, want_version) == 0
    lo_i = m.get("versionStartIncluding")
    lo_e = m.get("versionStartExcluding")
    hi_i = m.get("versionEndIncluding")
    hi_e = m.get("versionEndExcluding")
    if not any([lo_i, lo_e, hi_i, hi_e]):
        return True                       # product listed with no version bound
    if lo_i and _vcmp(want_version, lo_i) < 0:
        return False
    if lo_e and _vcmp(want_version, lo_e) <= 0:
        return False
    if hi_i and _vcmp(want_version, hi_i) > 0:
        return False
    if hi_e and _vcmp(want_version, hi_e) >= 0:
        return False
    return True


def _cpe_products(mapped_product: str, want_product: str) -> set[str]:
    out = set()
    if mapped_product:
        out.add(mapped_product.lower())
    if want_product:
        out.add(want_product.strip().lower().replace(" ", "_"))
    return out


def version_applies(cve_obj: dict, products: set[str], want_version: str) -> bool:
    """Keep a CVE only if our product+version falls inside its CPE ranges.

    Used for keyword-search results (which are not version-filtered by NVD).
    Conservative: if our product never appears in the CVE's configurations we
    keep the CVE (can't disprove it); we only drop it when our product IS listed
    but every matching node excludes our version.
    """
    if not want_version:
        return True
    matches = []
    for conf in cve_obj.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", False):
                    continue
                crit = m.get("criteria", "").lower()
                prod = crit.split(":")[4] if len(crit.split(":")) > 4 else ""
                if any(p and (p == prod or p in crit) for p in products):
                    matches.append(m)
    if not matches:
        return True
    return any(_match_cpe(m, want_version) for m in matches)


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


# NVD 2.0 allows up to 2000 results per page; we page through the whole result
# set (bounded by cfg.max_cve_fetch) rather than taking only the first page, so
# an old product with hundreds of CVEs (e.g. PHP 5.2.4 -> 324, with the KEV
# CVE-2012-1823 at index 105) does not silently lose everything past page one.
_NVD_PAGE = 2000


async def _nvd_page(http, cfg, base_qs: str, start: int, cache):
    """Fetch one NVD page (cached per start index). Returns the parsed payload
    dict, or None on failure."""
    import json
    qs = f"{base_qs}&resultsPerPage={_NVD_PAGE}&startIndex={start}"
    payload = cache.get(f"nvd:{qs}") if cache is not None else None
    if payload is not None:
        return payload
    headers = {"apiKey": cfg.nvd_api_key} if cfg.nvd_api_key else None
    r = await http.fetch(f"{NVD_URL}?{qs}", method="GET",
                         headers=headers, read_body=True)
    if not r.ok or r.status != 200:
        utils.debug(f"nvd {r.status} start={start}")
        return None
    try:
        payload = json.loads(r.text)
    except Exception as e:  # noqa: BLE001
        utils.debug(f"nvd parse: {e}")
        return None
    if cache is not None:
        cache.set(f"nvd:{qs}", payload)
    return payload


async def query_nvd(http, cfg: ScanConfig, cpe: str | None,
                    keyword: str | None, cache=None,
                    products: set[str] | None = None,
                    want_version: str = "") -> list[CVE]:
    params = {}
    if cpe:
        params["cpeName"] = cpe
        params["isVulnerable"] = ""        # only CVEs applicable to this CPE
    elif keyword:
        params["keywordSearch"] = keyword
    else:
        return []
    base_qs = "&".join(f"{k}={v}" for k, v in params.items()
                       if v != "" or k == "isVulnerable")

    # page through the full result set up to the fetch ceiling
    fetch_cap = max(_NVD_PAGE, getattr(cfg, "max_cve_fetch", _NVD_PAGE))
    vulns: list = []
    start = 0
    while True:
        payload = await _nvd_page(http, cfg, base_qs, start, cache)
        if payload is None:
            break
        page = payload.get("vulnerabilities", [])
        vulns.extend(page)
        total = payload.get("totalResults", len(vulns))
        start += _NVD_PAGE
        if start >= total or len(vulns) >= fetch_cap or not page:
            if total > fetch_cap:
                utils.debug(f"nvd: {cpe or keyword} has {total} CVEs, "
                            f"capped fetch at {fetch_cap}")
            break

    # keyword results are NOT version-filtered by NVD -> prune with CPE ranges
    if keyword and not cpe and products and want_version:
        before = vulns
        vulns = [it for it in before
                 if version_applies(it.get("cve", {}), products, want_version)]
        if len(vulns) != len(before):
            utils.debug(f"nvd kw: version-filtered {len(before)}->{len(vulns)}")

    try:
        return parse_nvd({"vulnerabilities": vulns})
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
async def epss_lookup(http, cfg, cve_ids: list[str],
                      cache=None) -> dict[str, tuple[float, float]]:
    """Map CVE-ID -> (epss_probability, percentile) via the FIRST.org EPSS API.

    EPSS estimates the probability a CVE is exploited in the wild in the next
    30 days. The API takes a comma-separated ``cve=`` list; we batch to stay
    within URL limits. Per-CVE results are cached so only unseen IDs are queried.
    """
    import json
    out: dict[str, tuple[float, float]] = {}
    ids = [c for c in cve_ids if c.startswith("CVE-")]
    if cache is not None:
        remaining = []
        for cid in ids:
            hit = cache.get(f"epss:{cid}", ttl=86400)
            if hit is not None:
                out[cid] = (hit[0], hit[1])
            else:
                remaining.append(cid)
        ids = remaining
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
                pair = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
            out[cid] = pair
            if cache is not None:
                cache.set(f"epss:{cid}", list(pair))
    return out


async def kev_lookup(http, cfg, cache=None) -> set[str]:
    """Return the set of CVE-IDs in the CISA Known Exploited Vulnerabilities
    catalog (cached for 6h; it is a multi-MB download)."""
    import json
    cached = cache.get("kev:catalog", ttl=21600) if cache is not None else None
    if cached is not None:
        return set(cached)
    r = await http.fetch(KEV_URL, method="GET", read_body=True)
    if not r.ok or r.status != 200:
        utils.debug(f"kev {r.status}")
        return set()
    try:
        data = json.loads(r.text)
    except Exception as e:  # noqa: BLE001
        utils.debug(f"kev parse: {e}")
        return set()
    ids = {v.get("cveID") for v in data.get("vulnerabilities", [])
           if v.get("cveID")}
    if cache is not None:
        cache.set("kev:catalog", sorted(ids))
    return ids


async def enrich(cfg, http, services: list[Service], cache=None) -> None:
    """Attach EPSS scores and CISA-KEV flags to every CVE already found, then
    re-rank each service's list so known-exploited / high-risk CVEs surface."""
    all_ids = sorted({c.id for s in services for c in s.cves
                      if c.id.startswith("CVE-")})
    if not all_ids:
        return

    epss_map: dict[str, tuple[float, float]] = {}
    kev_set: set[str] = set()
    if cfg.epss:
        epss_map = await epss_lookup(http, cfg, all_ids, cache=cache)
    if cfg.kev:
        kev_set = await kev_lookup(http, cfg, cache=cache)
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
async def correlate(cfg: ScanConfig, http, services: list[Service],
                    cache=None) -> None:
    """Attach CVEs to each service that has an identifiable product."""
    import httpx
    if cache is None:
        from .cache import Cache
        cache = Cache(enabled=getattr(cfg, "cve_cache", True),
                      ttl=getattr(cfg, "cache_ttl", 86400))

    async def osv_direct(name: str, version: str) -> list[CVE]:
        ckey = f"osv:{name}:{version}"
        payload = cache.get(ckey)
        if payload is None:
            try:
                async with httpx.AsyncClient(timeout=cfg.timeout, verify=False) as cl:
                    resp = await cl.post(OSV_URL,
                                         json={"package": {"name": name},
                                               "version": version})
                if resp.status_code == 200:
                    payload = resp.json()
                    cache.set(ckey, payload)
            except Exception as e:  # noqa: BLE001
                utils.debug(f"osv {name} {version}: {type(e).__name__}")
        return parse_osv(payload) if payload else []

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
                mapped = _CPE_MAP.get(svc.product.strip().lower())
                products = _cpe_products(mapped[1] if mapped else "", svc.product)
                for c in await query_nvd(http, cfg, cpe, kw, cache=cache,
                                         products=products,
                                         want_version=svc.version):
                    found.setdefault(c.id, c)
                if cpe:
                    utils.debug(f":{svc.port} nvd via {cpe}")
                    # A CPE that returns nothing usually means our vendor/product
                    # guess disagrees with NVD's naming (NVD renames vendors,
                    # e.g. vsftpd -> vsftpd_project). Fall back to a version-
                    # filtered keyword search so a naming miss doesn't zero out
                    # an otherwise well-known service.
                    if not found and svc.product:
                        kwfb = f"{svc.product} {svc.version}".strip()
                        for c in await query_nvd(http, cfg, None, kwfb, cache=cache,
                                                 products=products,
                                                 want_version=svc.version):
                            found.setdefault(c.id, c)
                        if found:
                            utils.debug(f":{svc.port} nvd cpe->kw fallback hit "
                                        f"({len(found)})")
            # --- OSV (open-source packages) ---
            if cfg.osv and svc.version:
                osv_name = _OSV_NAME.get(svc.product.lower())
                if osv_name:
                    for c in await osv_direct(osv_name, svc.version):
                        found.setdefault(c.id, c)

            # --- secondary products on the same port (PHP/ASP.NET via
            #     X-Powered-By, etc.): own CVE subjects the single-product
            #     Service would otherwise never query (e.g. PHP CVE-2012-1823).
            if cfg.nvd:
                for pair in getattr(svc, "aux", []):
                    ap, av = (pair + ["", ""])[:2]
                    acpe = make_cpe(ap, av)
                    if not acpe:
                        continue          # only correlate products we can map
                    amapped = _CPE_MAP.get(ap.strip().lower())
                    aprods = _cpe_products(amapped[1] if amapped else "", ap)
                    for c in await query_nvd(http, cfg, acpe, None, cache=cache,
                                             products=aprods, want_version=av):
                        found.setdefault(c.id, c)
                    utils.debug(f":{svc.port} aux nvd via {acpe}")

            cves = [c for c in found.values()
                    if (c.cvss is None or c.cvss >= cfg.min_cvss)]
            cves.sort(key=lambda c: (-(c.cvss or 0), c.id))
            # keep the FULL set here; the display cap is applied in correlate()
            # after KEV/EPSS enrichment so known-exploited / high-severity CVEs
            # are never trimmed before they are ranked.
            svc.cves = cves
            if svc.cves:
                crit = sum(1 for c in svc.cves if (c.cvss or 0) >= 9)
                utils.hit(f":{svc.port} {svc.ident()} -> {len(svc.cves)} CVEs "
                          f"({crit} critical)")

    await asyncio.gather(*(one(s) for s in services))

    # --- enrichment: EPSS probabilities + CISA KEV flags across all findings ---
    if cfg.epss or cfg.kev:
        await enrich(cfg, http, services, cache=cache)

    # --- display cap: applied AFTER KEV/EPSS so a known-exploited or critical
    #     CVE sitting past the cap by CVSS alone is not dropped before ranking.
    cap = cfg.max_cves_per_service
    for svc in services:
        if len(svc.cves) > cap:
            svc.cves.sort(key=lambda c: (not c.kev, -(c.cvss or 0),
                                         -(c.epss or 0), c.id))
            svc.cves = svc.cves[:cap]

    # --- exploit availability (ExploitDB / Metasploit / GitHub PoC) ---
    if getattr(cfg, "exploits", False):
        from . import exploits as exploit_mod
        await exploit_mod.enrich_exploits(cfg, http, services, cache=cache)
