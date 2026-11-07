# webrecon

> Full-featured, async web crawler & recon toolkit — katana-style, but it also
> mines JavaScript, probes liveness, enumerates subdomains, discovers virtual
> hosts from TLS certificates, and hunts for leaked secrets.

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-beta-orange)
![async](https://img.shields.io/badge/engine-asyncio-purple)

One command runs the whole recon pipeline: render-crawl a target, extract
endpoints and parameters from HTML and JS, check what's alive, enumerate
subdomains, discover hidden vhosts from certificate SANs, and scan every
response for API keys, tokens, passwords and other secrets.

---

## Features

| Capability | What it does |
|---|---|
| **JS-aware crawl** | Headless/headed Chromium (Playwright). Catches links injected by JS and URLs hit via `fetch`/`axios`/XHR, not just static HTML. `--no-render` falls back to fast HTTP-only. |
| **Endpoint & URL extraction** | Pulls paths, endpoints and full URLs from external + inline JavaScript (LinkFinder-style regex + API-call detection). |
| **Parameter mapping** | Separates parameterized vs. parameterless endpoints and records observed parameter names per endpoint. |
| **Liveness check** | Probes discovered URLs and hosts; reports status, final URL, title, and `Server` header. |
| **Subdomain enumeration** | Passive enum via crt.sh (Certificate Transparency) + optional wordlist. |
| **Cert → vhost discovery** | Reads `subjectAltName` DNS names from the target's TLS certificate, then fuzzes the `Host:` header against the shared IP to surface hidden virtual hosts (baseline-divergence detection). |
| **Secret scanning** | AWS / GCP / GitHub / GitLab / Slack / Stripe / OpenAI / Anthropic keys, JWTs, private-key blocks, DB connection strings, basic-auth-in-URL, and generic `password=/token=/secret=/apikey=/username=` assignments — with entropy + placeholder filtering. Findings are redacted, severity-tagged, with source + line. |
| **Clean output** | Full `report.json` plus greppable `*.txt` lists, and a colored console summary. |

---

## Install

Requires Python 3.10+.

### Quick (recommended): virtualenv via setup script

```bash
git clone https://github.com/kemrec/webrecon.git
cd webrecon
./setup.sh                 # creates .venv, installs deps, fetches Chromium
source .venv/bin/activate
webrecon https://example.com
```

### Manual virtualenv

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .                   # or: pip install -r requirements.txt
python -m playwright install chromium   # once, for JS rendering
```

After `pip install -e .` the `webrecon` command is on your PATH inside the venv.
Without installing, run it as a module: `python -m webrecon <target> ...`.

> **Tip:** always work inside the venv so dependencies don't touch your system
> Python. `deactivate` leaves the environment.

---

## Usage

```bash
# full pipeline (rendering on)
webrecon https://example.com

# deeper crawl, more concurrency
webrecon example.com -d 3 --max-pages 500 -c 60

# fast, HTTP-only (no JS rendering)
webrecon https://example.com --no-render

# only JS mining + secret scanning
webrecon example.com --only js,secrets

# crawl + alive only, skip discovery
webrecon example.com --skip vhost,subs

# wordlist-driven discovery, custom output dir
webrecon example.com --vhost-wordlist hosts.txt --subdomain-wordlist subs.txt -o out/

# extra headers / proxy / headed debug
webrecon example.com -H "Cookie: sid=abc" -H "X-Api-Key: k" \
         --proxy http://127.0.0.1:8080 --headful
```

### Phase names (`--only` / `--skip`)

| Name | Phase |
|------|-------|
| `crawl`   | page crawling |
| `js`      | JS endpoint/param extraction |
| `secrets` | secret scanning |
| `subs`    | subdomain enumeration (crt.sh + wordlist) |
| `vhost`   | cert SAN + Host-header vhost fuzzing |
| `alive`   | liveness probing |

### Common options

| Flag | Default | Meaning |
|------|---------|---------|
| `-d, --depth` | `2` | crawl depth |
| `--max-pages` | `300` | hard page cap |
| `--no-render` | off | disable Playwright, HTTP-only |
| `--headful` | off | run browser headed (debug) |
| `-c, --concurrency` | `40` | async concurrency |
| `-t, --timeout` | `12` | per-request timeout (s) |
| `-H, --header` | — | extra header, repeatable (`K:V`) |
| `--proxy` | — | HTTP(S) proxy URL |
| `--verify-tls` | off | verify TLS certs (recon default: off) |
| `-o, --outdir` | `webrecon-out` | output directory |
| `-q / -v` | — | quiet / verbose |

Full list: `webrecon -h`.

---

## Output

Written to `-o` (default `webrecon-out/`):

- `report.json` — complete machine-readable results
- `urls.txt`, `js_files.txt`, `endpoints.txt`
- `params.txt` — `endpoint<TAB>param1,param2`
- `subdomains.txt`, `alive.txt`, `vhosts.txt`
- `secrets.txt` — `[SEVERITY] type  preview  source:line`

A colored summary and the top secret findings are printed to the console.

---

## How it works

```
 ┌───────────┐   ┌─────────────┐   ┌──────────────┐   ┌────────┐   ┌────────┐
 │ 1. Crawl  │──▶│ 2. Discovery │──▶│ 3. Shallow   │──▶│ 4.Alive│──▶│5.Report│
 │ render+JS │   │ cert/crt.sh  │   │ crawl vhosts │   │ probe  │   │ json+txt│
 │ +secrets  │   │ +vhost fuzz  │   │ /subdomains  │   │        │   │        │
 └───────────┘   └─────────────┘   └──────────────┘   └────────┘   └────────┘
```

1. **Crawl** — render each page, collect DOM links, inline/external JS and
   network requests; fetch external JS and extract endpoints, parameters and
   secrets; enqueue in-scope links (BFS, bounded by depth/max-pages).
2. **Discovery** — gather candidate hosts from the TLS cert SANs and crt.sh,
   resolve them, then fuzz the `Host:` header against shared IPs.
3. **Shallow crawl** — lightly crawl newly found live vhosts/subdomains.
4. **Alive** — probe all URLs and hosts.
5. **Report** — aggregate into JSON + txt + console summary.

---

## Notes

- TLS verification is **off** by default for recon (`--verify-tls` to enable).
- Rendering spawns a browser context per page, so render-mode uses fewer
  workers; `--no-render` is much faster but misses JS-dynamic links.
- crt.sh and DNS resolution need outbound access; on restricted networks those
  phases may return empty.

---

## Legal

For use **only** against systems you own or are explicitly authorized to test.
Unauthorized scanning is illegal and entirely your responsibility.

## License

[MIT](LICENSE) © 2026 Kaya Emre Arıkan
