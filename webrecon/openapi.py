"""OpenAPI / Swagger spec discovery.

An API's OpenAPI (a.k.a. Swagger) document enumerates its entire route and
parameter surface in one file, including endpoints a crawler never reaches
(no links, auth-gated, non-GET). We probe a short list of well-known spec
locations and, when one is served, parse every path + query parameter out of
it and fold them into the crawl's endpoint/param/URL surface.

Only read-only GETs of conventional spec URLs are made. JSON specs are parsed
natively; YAML is parsed only if PyYAML happens to be importable (the URL is
still recorded either way), so this module adds no hard dependency.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from . import utils

# Well-known spec locations (OpenAPI 3 + Swagger 2 conventions, common
# frameworks: springdoc, drf-yasg/spectacular, FastAPI, NSwag, go-swagger).
SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api-docs.json",
    "/api/swagger.json", "/api/openapi.json", "/api/v1/openapi.json",
    "/api/schema/", "/schema/", "/docs/openapi.json",
    "/.well-known/openapi.json",
]

_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "trace"}


def _looks_like_spec(d) -> bool:
    return isinstance(d, dict) and ("openapi" in d or "swagger" in d) and "paths" in d


def _load_spec(text: str, content_type: str):
    """Parse a spec body as JSON, or YAML when PyYAML is available. None if it
    is neither a spec nor parseable."""
    text = (text or "").lstrip("﻿ \t\r\n")
    if not text:
        return None
    if text[:1] in "{[":
        try:
            d = json.loads(text)
            return d if _looks_like_spec(d) else None
        except ValueError:
            return None
    # YAML (optional): only try when it plausibly is a spec document
    head = text[:200].lower()
    if "openapi:" in head or "swagger:" in head:
        try:
            import yaml  # type: ignore
        except Exception:  # noqa: BLE001
            return None
        try:
            d = yaml.safe_load(text)
            return d if _looks_like_spec(d) else None
        except Exception:  # noqa: BLE001
            return None
    return None


def _bases(spec: dict) -> list[str]:
    """Route prefixes: OpenAPI-3 `servers[].url` (absolute or relative) and
    Swagger-2 `basePath`. Empty prefix if none."""
    out: list[str] = []
    servers = spec.get("servers")
    if isinstance(servers, list):
        for s in servers:
            if isinstance(s, dict) and s.get("url"):
                out.append(str(s["url"]))
    base_path = spec.get("basePath")
    if isinstance(base_path, str) and base_path:
        out.append(base_path)
    return out or [""]


def _join(base: str, path: str) -> str:
    """Endpoint path = base-prefix + path, normalised to a single leading slash.
    If base is an absolute URL, only its path component is used."""
    if base.startswith(("http://", "https://")):
        base = urlsplit(base).path
    base = base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return (base + path) or "/"


def parse_spec(spec: dict, spec_url: str):
    """Pure extraction: return (endpoints:set, params:{ep:set}, urls:set, meta).
    Endpoints are host-less route paths (templates kept, e.g. /users/{id});
    urls are absolute, resolved against the spec's own origin / servers."""
    endpoints: set[str] = set()
    params: dict[str, set[str]] = {}
    urls: set[str] = set()
    sp = urlsplit(spec_url)
    origin = f"{sp.scheme}://{sp.netloc}" if sp.scheme else ""
    bases = _bases(spec)
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        paths = {}

    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        qkeys: set[str] = set()
        raw_params = []
        if isinstance(item.get("parameters"), list):     # path-level params
            raw_params += item["parameters"]
        for meth, op in item.items():
            if meth.lower() in _METHODS and isinstance(op, dict) \
                    and isinstance(op.get("parameters"), list):
                raw_params += op["parameters"]            # operation-level params
        for prm in raw_params:
            if isinstance(prm, dict) and prm.get("in") == "query" and prm.get("name"):
                qkeys.add(str(prm["name"]))

        for base in bases:
            ep = _join(base, path)
            endpoints.add(ep)
            if qkeys:
                params.setdefault(ep, set()).update(qkeys)
            if base.startswith(("http://", "https://")):
                urls.add(base.rstrip("/") + ("" if path.startswith("/") else "/") + path)
            elif origin:
                urls.add(origin + ep)

    info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
    meta = {
        "url": spec_url,
        "title": str(info.get("title", "")),
        "version": str(info.get("version", "")),
        "openapi": str(spec.get("openapi") or spec.get("swagger") or ""),
        "paths": len(paths),
        "endpoints": len(endpoints),
    }
    return endpoints, params, urls, meta


async def discover(cfg, http, base_urls):
    """Probe each base URL for well-known spec paths; parse any specs found.
    Returns (specs:list[meta], endpoints:set, params:dict, urls:set)."""
    specs: list[dict] = []
    endpoints: set[str] = set()
    params: dict[str, set[str]] = {}
    urls: set[str] = set()
    seen_urls: set[str] = set()
    seen_specs: set[str] = set()      # dedupe by (title, paths) fingerprint

    for base in base_urls:
        base = base.rstrip("/")
        for path in SPEC_PATHS:
            full = base + path
            if full in seen_urls:
                continue
            seen_urls.add(full)
            try:
                r = await http.fetch(full)
            except Exception:  # noqa: BLE001
                continue
            if not r or r.status != 200 or not r.text:
                continue
            spec = _load_spec(r.text, r.content_type)
            if not spec:
                continue
            eps, ps, us, meta = parse_spec(spec, r.final_url or full)
            fp = f"{meta['title']}|{meta['paths']}|{sorted(eps)[:1]}"
            if fp in seen_specs:
                continue
            seen_specs.add(fp)
            specs.append(meta)
            endpoints |= eps
            for k, v in ps.items():
                params.setdefault(k, set()).update(v)
            urls |= us
            utils.good(f"openapi: {meta['title'] or 'spec'} "
                       f"({meta['paths']} paths, {len(eps)} endpoints) at {full}")
    return specs, endpoints, params, urls
