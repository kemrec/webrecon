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

This repo ships **two CLIs** that share one async core:

| Tool | Purpose |
|------|---------|
| **`webrecon`** | web app crawler & recon (crawl + JS + params + alive + subdomains + vhost + secrets) |
| **`servicescan`** | port/service/version discovery (nmap + own fingerprint layer) with NVD/OSV CVE correlation |

---

## Features — webrecon

| Capability | What it does |
|---|---|
| **JS-aware crawl** | Headless/headed Chromium (Playwright). Catches links injected by JS and URLs hit via `fetch`/`axios`/XHR, not just static HTML. `--no-render` falls back to fast HTTP-only. |
| **Endpoint & URL extraction** | Pulls paths, endpoints and full URLs from external + inline JavaScript (LinkFinder-style regex + API-call detection). |
| **Parameter mapping** | Separates parameterized vs. parameterless endpoints and records observed parameter names per endpoint. |
| **OpenAPI / Swagger discovery** | Probes well-known spec locations (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, …) on the target and discovered hosts, parses any spec (OpenAPI 3 + Swagger 2, JSON; YAML when PyYAML is present), and folds every route + query parameter into the endpoint/param/URL surface — including endpoints the crawler can't reach. Read-only GETs only. |
| **Liveness check** | Probes discovered URLs and hosts; reports status, final URL, title, and `Server` header. |
| **Subdomain enumeration** | Passive enum via crt.sh (Certificate Transparency) + optional wordlist. |
| **Cert → vhost discovery** | Reads `subjectAltName` DNS names from the target's TLS certificate, then fuzzes the `Host:` header against the shared IP to surface hidden virtual hosts (baseline-divergence detection). |
| **Secret scanning** | 50+ provider rules (gitleaks / truffleHog family): AWS / Azure / GCP / DigitalOcean / Vault / GitHub / GitLab / Atlassian / Slack / Discord / Telegram / Twilio / SendGrid / Stripe / Square / PayPal / npm / PyPI / OpenAI / Anthropic / HuggingFace / Shopify / Datadog / New Relic / Postman / Databricks / Notion / Grafana / Mapbox / Dropbox keys, JWTs, private-key blocks, DB connection strings, basic-auth-in-URL, and generic `password=/token=/secret=/apikey=/username=` assignments — with entropy + placeholder filtering. `--aggressive` adds an opt-in entropy sweep for secret-shaped strings under unrecognised key names (gitleaks `generic-api-key`; noisier, rated low). Findings carry the full value (operator tool, not redacted), severity-tagged, with source + line. |
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
| `openapi` | OpenAPI/Swagger spec discovery + route extraction |

### Common options

| Flag | Default | Meaning |
|------|---------|---------|
| `-d, --depth` | `2` | crawl depth |
| `--max-pages` | `300` | hard page cap |
| `--no-render` | off | disable Playwright, HTTP-only |
| `--headful` | off | run browser headed (debug) |
| `--render-workers` | `3` | max concurrent browser tabs in render mode |
| `--no-block-resources` | off | also load images/media/fonts (default: aborted) |
| `--max-js-bytes` | `20000000` | skip parsing JS bundles bigger than this |
| `--aggressive` | off | secrets: also flag secret-shaped high-entropy strings under unknown key names (noisier, all rated low) |
| `-c, --concurrency` | `40` | async concurrency |
| `-t, --timeout` | `12` | per-request timeout (s) |
| `-H, --header` | — | extra header, repeatable (`K:V`) |
| `--cookie` | — | Cookie header for authenticated crawling |
| `--bearer` | — | `Authorization: Bearer TOKEN` for authenticated crawling |
| `--proxy` | — | HTTP(S) proxy URL |
| `--verify-tls` | off | verify TLS certs (recon default: off) |
| `-o, --outdir` | `webrecon-out` | output directory |
| `-q / -v` | — | quiet / verbose |

Full list: `webrecon -h`.

### Resource usage (render mode)

JS rendering is the expensive part of any crawler. webrecon keeps CPU/memory
bounded without losing discovery:

- **One shared browser per crawl**, reused across pages (not a launch per page),
  with each page in its own context that is torn down right after — memory does
  not accumulate across pages.
- **Bounded parallelism**: at most `--render-workers` (3) tabs open at once;
  the `--web` chain processes hosts and ports sequentially, so a `/24` scan
  never spawns many browsers in parallel.
- **Heavy resources aborted**: images, media and fonts are dropped during
  render. Their request URLs are still recorded (so discovery is unaffected) —
  only the download/decode is skipped, which is the bulk of the cost. On a
  typical heavy page this cuts completed network work by ~65–70%. Use
  `--no-block-resources` to load them anyway.
- **Hard caps** on pages (`--max-pages`), depth (`-d`), per-page time
  (`--page-timeout`) and JS parse size (`--max-js-bytes`).
- Render is **off** inside the `--web` chain unless you pass `--web-render` /
  `--full`; plain HTTP crawling barely uses the CPU at all.

On a constrained box, `--render-workers 1` (or `--no-render`) is the safe dial.

---

## Output — webrecon

Each run is filed under its own target + timestamp directory, so re-scanning a
target or scanning a new one never overwrites a prior result:

```
webrecon-out/
  example.com/
    20261119-071500/    # one run
      report.json  urls.txt  endpoints.txt  params.txt  ...
    20261119-073012/    # a later run
    latest -> 20261119-073012
```

`-o/--outdir` sets the base directory; `--flat` writes straight into it (legacy
single-directory behaviour). Files in each run directory:

- `report.json` — complete machine-readable results
- `urls.txt`, `js_files.txt`, `endpoints.txt` — scope-confined attack surface
- `external.txt` — off-scope references seen on target pages (intel, not probed)
- `params.txt` — `endpoint<TAB>param1,param2`
- `subdomains.txt`, `alive.txt`, `vhosts.txt`
- `secrets.txt` — `[SEVERITY] type  value  source:line` (full value, not redacted)
- `tech.txt` — detected technologies (server, framework, CMS, JS libs)
- `forms.txt` — `METHOD<TAB>action-url<TAB>field1,field2` for every HTML form
- `openapi.txt` — any OpenAPI/Swagger spec found (`spec-url<TAB>title vN<TAB>N paths<TAB>N endpoints`); its routes also merge into `endpoints.txt` / `params.txt` / `urls.txt`

A live progress bar (TTY only), a colored summary, and the top secret findings
are printed to the console.

---

## How webrecon works

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

## servicescan — service/version discovery + CVE correlation

A second CLI for the host/network side. It wraps **nmap** for the heavy
lifting (port scan + `-sV` service detection), then runs **its own
fingerprint layer** to recover versions nmap leaves blank, and finally
correlates every `(product, version)` against **NVD** and **OSV** to list
known CVEs. Each CVE is then enriched with its **EPSS** score (FIRST.org
exploitation probability) and flagged if it appears in the **CISA KEV**
catalog of vulnerabilities known to be exploited in the wild — so the output
ranks by real-world risk, not just CVSS.

### Why a layer on top of nmap?

nmap's `-sV` is excellent on classic TCP services but often returns a bare
`http`/`unknown` with no product or version — especially for web apps behind
a reverse proxy (WordPress behind nginx, Jira, Grafana, …). servicescan takes
nmap's result and, for every under-identified port, adds:

- **banner grab** (with protocol-appropriate nudges for SSH/FTP/SMTP/Redis/…),
- **HTTP fingerprint** (`Server` / `X-Powered-By` headers, `generator` meta,
  body signatures for common apps + their versions), backed by a 299-app
  technology catalog (header/meta/cookie/script/HTML signals with version
  capture) that feeds CVE correlation,
- **`--render` (opt-in)**: renders each web port's root with Playwright and
  evaluates the catalog's JavaScript-global and DOM signals, so apps whose only
  fingerprint is a `window.*` global or a DOM selector (Angular, CKEditor,
  Ember.js, GrapesJS, Vtiger, Kubernetes Dashboard, …) are detected too. Their
  versions land in the native port-scan summary and CVE output — no separate
  webrecon crawl needed. (A full `--web` crawl also runs the catalog, including
  these rendered signals, and lists what it found per port.)
- **TLS certificate** (subject/issuer/SAN, often naming the host/app),
- **discovery path-probes** (read-only) for high-value apps that expose no
  landing-page fingerprint: Apache Solr (`/solr/admin/info/system` → exact
  version), Oracle WebLogic (`/console/` → presence), Appwrite
  (`/v1/health/version` → version). One GET each; a versioned hit feeds CVE,
- **silent binary-protocol probes** for services that never send a banner:
  AJP13 (CPing/CPong, Ghostcat surface), distcc on 3632 (read-only behavioural
  probe, CVE-2004-2687 unrestricted-exec exposure), plus unauthenticated
  bindshell detection,
- **unauthenticated-exposure checks** (read-only, run on every open port, not
  just the under-identified ones): Redis `INFO`, memcached `version`, MongoDB
  `listDatabases`, Elasticsearch cluster root, CouchDB `/_all_dbs`, Docker
  Engine API `/version`, etcd `/v2/keys`, and kubelet `/pods` (anonymous auth)
  confirm whether a store or control-plane endpoint answers without
  credentials. An open one is flagged as a critical finding (and, where
  available, the probe also recovers the version); a credential-protected one
  is reported as such. The probes send only non-mutating GET/commands and
  never write or delete — e.g. etcd exposure is confirmed only when the v2
  keyspace is actually readable, not from the always-public `/version`.
- **RTSP/RTSPS camera checks** (ports 554/8554/… or any `rtsp` service; RTSP
  over TLS on 322 or an `rtsps`/`ssl` service): a read-only `OPTIONS` names the
  device and lists methods, and an unauthenticated `DESCRIBE` over common stream
  paths (Hikvision/Dahua/Axis/Reolink/Foscam/Hanwha/generic) detects an **open
  stream** (`200` + SDP → critical: anyone can view the feed) versus a gated one
  (`401` → the auth scheme/realm is recorded). On a gated stream it also tries a
  tiny list of factory-default credentials (`admin:admin`, `root:root`, …) over
  Basic **and** Digest; an accepted default is a critical finding. RTSPS runs the
  identical recon over a TLS transport. Nothing is ever `PLAY`ed or recorded.
- **ONVIF camera checks** (any web port or a common ONVIF port): a SOAP
  `GetSystemDateAndTime` (unauthenticated by spec) confirms an ONVIF
  `device_service` and reads the device clock; an unauthenticated
  `GetDeviceInformation` either returns make/model/firmware/serial (**critical**
  misconfiguration) or faults (gated). On a gated device it tries the same
  factory-default list via a WS-UsernameToken `PasswordDigest`; an accepted
  default exposes the camera's management API (media URIs, users, PTZ) and is
  critical. Once access is confirmed (either way), read-only `GetUsers` lists the
  device's accounts and privilege levels, and `GetProfiles` + `GetStreamUri` +
  `GetSnapshotUri` list the media profiles (stream name, resolution, codec) with
  the **actual stream/snapshot URIs** the device serves (these frequently embed
  the stream credentials in clear) — the media endpoint is discovered via
  `GetServices`. Read-only SOAP calls only.
- **Unauth JPEG snapshot** (any camera-signalled web port): most IP cameras
  expose a still-frame URL (`/snapshot.jpg`, `/axis-cgi/jpg/image.cgi`,
  `/ISAPI/Streaming/channels/101/picture`, …). A single read-only `GET` that
  returns a JPEG of the live view is a direct **critical** confirmation that the
  feed is viewable without credentials. Gated to a camera signal (vendor banner /
  ONVIF present / camera port) so unrelated web servers are never probed.
- **ONVIF WS-Discovery** (UDP 3702): a unicast `Probe` for the ONVIF
  `NetworkVideoTransmitter` type makes a camera/NVR answer — without auth — with
  its Types, Scopes (`onvif://…/name|hardware|location`) and the `device_service`
  XAddr. Run once per host (one datagram, unicast only), so it surfaces cameras a
  default TCP scan misses.
- **Vendor camera CGI** (camera-signalled web port): the HTTP management API that
  Hikvision (`/ISAPI/System/deviceInfo`), Dahua (`/cgi-bin/magicBox.cgi`) and Axis
  (`/axis-cgi/param.cgi`) cameras expose beside RTSP/ONVIF. A read-only `GET` that
  returns device info **without credentials** is a **critical** misconfiguration
  (the CVE-2017-7921 ISAPI class); a `401` is probed with a tiny default-credential
  list over HTTP Basic/Digest, and an accepted default (model + firmware recovered,
  fed to CVE correlation) is **critical**. The cred test is self-limiting — a path
  the device doesn't implement `404`s, so defaults are only tried against the API
  the device actually speaks — and is governed by the same `--no-cam-creds` switch.
- **gRPC / HTTP2** (dedicated gRPC ports — 50051/6565/9090/… — or a `grpc`-named
  service): dependency-free detection (TLS ALPN `h2`, or the cleartext h2c
  preface → SETTINGS frame). The real finding is **server reflection enabled
  without authentication**, which lets anyone enumerate every service (the gRPC
  analogue of an open Swagger) — reported as critical with the service list. The
  reflection `list_services` call is done **natively, with no dependency**: the
  service names come back in the response DATA frame (protobuf), not the HPACK
  headers, so only HPACK *encoding* (literals, no Huffman) plus a tiny protobuf
  reader are needed — no gRPC library. `grpcurl`/`grpcio` are used only as an
  optional fallback if the native client can't complete the exchange. Scoped to
  gRPC ports so HTTPS/2 web ports are never mislabelled. Read-only (list only).
- **Ops / control-plane HTTP services** (read-only GETs, each gated to its port
  or a matching service name): **Prometheus** (`/-/healthy` + `buildinfo`; no
  auth by design, so network-reachable = **critical** metrics/topology
  exposure), **Consul** (`/v1/agent/self` readable = ACLs disabled, **critical**
  catalog/KV exposure), **RabbitMQ** management (`/api/overview` without creds =
  **critical**), **MinIO** (anonymous `ListBuckets` = **critical**; detected via
  the `Server: MinIO` header), **Portainer** (`/api/users/admin/check` → `404`
  means **no admin is set yet**, so anyone can claim it and take over every
  Docker/K8s environment it manages — **critical**), **Apache ZooKeeper** (the
  four-letter-word `stat` over TCP = **critical** config/znode exposure), and
  **HashiCorp Vault** (`/v1/sys/seal-status`; this endpoint is unauthenticated by
  design, so Vault is reported **informationally** — product, version and
  sealed/unsealed state — as a hardening note, not an unauth-data finding). These
  share ports with the gRPC detector (MinIO/Portainer on 9000, Prometheus on
  9090); a confirmed product wins and only a genuine miss falls through to gRPC.
- **SNMP** (UDP 161): a hand-built (no `pysnmp` dependency) `GetRequest` for
  `sysDescr.0` with the well-known community strings `public`/`private`, over
  both SNMP v2c and v1. A reply is a **critical** finding — the whole MIB
  (interfaces, ARP/routing tables, processes, and on many devices credentials)
  is readable, and a writable community also allows configuration changes. The
  recovered `sysDescr` is included. Run once per host (161 is rarely in a default
  TCP scan); the four attempts race so the probe is bounded by one short timeout.
  Read-only (`GET` only, never `SET`).
- **IPMI cipher-zero** (UDP 623): an RMCP+ Open Session Request with every
  algorithm (auth/integrity/confidentiality) set to 0. A BMC that answers with
  status 0 accepts **cipher suite 0** — an administrative session with no
  password, i.e. full out-of-band control of the server (power, serial-over-LAN,
  virtual media, BMC user management): **critical**. A BMC that answers but
  refuses it is still reported (with a note on the IPMI 2.0 RAKP hash-disclosure
  exposure). Read-only — the probe never completes RAKP or issues a command, so
  no session is actually established.

The camera default-credential attempt (RTSP + ONVIF) is the one active step;
disable it with `--no-cam-creds` (alias `--no-rtsp-creds`) for a fully
read-only run.

Evidence is merged by confidence, so nmap's good answers are kept and only the
gaps get filled. The result is strictly **≥ nmap** on version coverage — not a
claim to replace nmap's signature database, but to finish the job where `-sV`
gives up.

> **Reality check:** servicescan does not reimplement nmap's probe database.
> It *wraps* nmap and augments it. With `--no-nmap` it still works on a set of
> common ports using only its own probes, but port coverage is then limited —
> keep nmap installed for full-port scans.

### How servicescan works

```
 ┌──────────────┐   ┌──────────────────┐   ┌─────────────────────┐   ┌────────┐
 │ 1. nmap -sV  │──▶│ 2. fingerprint   │──▶│ 3. CVE correlation  │──▶│4.Report│
 │ (full port)  │   │  fill nmap gaps  │   │  NVD + OSV by CPE   │   │json+txt│
 │  XML parse   │   │  banner/HTTP/TLS │   │  + EPSS + CISA KEV  │   │        │
 └──────────────┘   └──────────────────┘   └─────────────────────┘   └────────┘
                                      (--web) hand web ports + cert SANs │
                                      webrecon crawl per HTTP(S) port ◀──┘
```

### Install (adds nmap)

servicescan needs the `nmap` binary on PATH (the Python deps come with the
package):

```bash
# Debian/Ubuntu/Kali
sudo apt install nmap
# macOS
brew install nmap
```

### Usage

```bash
servicescan 10.0.0.5                      # full-port nmap + fingerprint + CVEs
servicescan scanme.nmap.org -p 1-1000     # limited port range
servicescan 10.0.0.5 --top-ports 1000 --rate 2000
servicescan host --fp-all                 # fingerprint every open port, not just gaps
servicescan host --no-cve                 # service/version detection only
servicescan host --min-cvss 7             # only show CVSS >= 7.0
servicescan host --kev-high               # reports show only KEV or HIGH/CRITICAL (scan.json keeps all)
servicescan 10.0.0.5 --no-cam-creds       # camera recon (RTSP+ONVIF) read-only, no default-cred test
servicescan host --no-epss --no-kev       # CVEs only, skip risk enrichment
servicescan host --no-nmap -p 80,443,8080 # fingerprint-only, no nmap
servicescan host --exploits               # map CVEs to public exploits/PoCs
servicescan host --nse                    # also run nmap NSE 'vuln' scripts
servicescan host --udp -p 53,161,123      # UDP services (needs root, slower)
NVD_API_KEY=xxxx servicescan host         # raise NVD rate limit (recommended)
```

#### Exploit mapping, NSE, UDP, and caching

- `--exploits` maps each found CVE to public exploits/PoCs from three sources:
  the local **ExploitDB** CSV (shipped with `exploitdb`/searchsploit on Kali),
  **Metasploit** module metadata if present, and the **PoC-in-GitHub** index
  (cached). CVEs with a known exploit re-rank to the top and get an
  `[EXPLOIT xN]` badge; the first link is in `report.html` and `cves.csv`.
- `--nse` runs nmap NSE scripts (default category `vuln`, override with
  `--nse-scripts`). Output lands in `scripts.txt` and `scan.json`.
- `--udp` adds a UDP service scan (`-sU`; needs root and is much slower).
  UDP ports reported `open|filtered` are kept.
- CVE / EPSS / KEV / OSV lookups are **cached to disk** (`~/.cache/servicescan`)
  so re-runs are 2-3x faster and stay under the NVD rate limit. `--no-cache`
  disables it; `--cache-ttl SECONDS` tunes freshness. Keyword-search NVD
  results are additionally filtered by **CPE version range**, so a CVE whose
  fixed/affected range excludes the detected version is dropped.
- **Environmental refinement.** A CVE can match the version correctly yet be
  inapplicable to *this* deployment. ALPACA (`CVE-2021-3618`) is a cross
  protocol TLS attack, so it only has meaning when the FTP service actually
  offers TLS. When the correlated version carries it, servicescan runs a
  strictly read-only `AUTH TLS` probe (inspect `FEAT`, else read the `AUTH`
  reply code; the TLS handshake is never started) against only that FTP
  service, and on a plaintext-only server it demotes the finding to a `LOW`
  display with an explanatory note. The canonical CVSS and the fact that the
  version is affected are preserved in `scan.json` / `cves.csv`
  (`eff_cvss`, `eff_severity`, `env_note` columns), so no intel is lost.

#### Targets: one host, many hosts, a range, or a file

The target can be a single IP/hostname or several at once. Each host is scanned
and then runs the fingerprint + CVE (+ optional `--web`) pipeline independently,
reported under its own block. Accepted forms (mix freely):

```bash
servicescan 10.0.0.5                       # single IP or hostname
servicescan 10.0.0.5 10.0.0.6 app.lab      # several targets in one run
servicescan 10.0.0.5,10.0.0.6              # comma-separated also works
servicescan 10.0.0.0/24                    # a CIDR block
servicescan 10.0.0.1-50                    # an nmap-style range (any octet)
servicescan -iL targets.txt                # read targets from a file
servicescan 10.0.0.0/24 --web --min-cvss 7 # whole subnet, web-chain, high CVEs
```

`-iL FILE` reads one target per line (`#` comments allowed; commas/spaces split
too). With nmap present, the whole spec is scanned in a single nmap invocation
(it expands CIDR/ranges/lists natively); in `--no-nmap` mode servicescan expands
the spec itself. Results group per host in the console, in `scan.json`
(`hosts[]`), and host-prefixed in `services.txt` / `cves.txt`. With `--web`,
each host gets its own `web/<ip>/<port>-<scheme>/` output subtree.

Key flags: `-iL/--target-file`, `-p/--ports`, `--top-ports`, `--rate` (nmap `--min-rate`),
`--no-nmap`, `--udp`, `--nse`, `--nse-scripts`, `--fp-all`, `--render`, `--no-cam-creds`, `--no-cve`,
`--no-nvd`, `--no-osv`, `--no-epss`, `--no-kev`, `--exploits`, `--nvd-api-key`,
`--min-cvss`, `--kev-high`, `--no-cache`, `--cache-ttl`, `--web`, `--full`, `--web-render`,
`--web-depth`, `--web-max-pages`, `--write-hosts`, `-c/--concurrency`,
`-t/--timeout`, `-o/--outdir`. Full list: `servicescan -h`.

Every scan writes, alongside `scan.json`: `services.txt`, `cves.txt`,
`services.csv`, `cves.csv`, `scan.jsonl` (one service per line), two nuclei
target lists (`nuclei-targets.txt` = web `scheme://host:port`, and
`nuclei-targets-net.txt` = non-web `host:port` for network/ssl templates), and a
standalone `report.html` (summary cards + per-host service/CVE tables with CVSS
colouring and KEV/exploit badges). `scripts.txt` is added when `--nse` ran.

### Web chain (`--web`): scan, then crawl every web port

`--web` turns the two tools into one pipeline: servicescan does the port /
service / CVE pass, then hands every discovered HTTP(S) port to webrecon, which
crawls it, mines JS, and scans for secrets. Per-port webrecon output lands under
`<outdir>/web/<port>-<scheme>/`, and a compact summary is attached to each
service in `scan.json` (and the console).

```bash
servicescan 10.0.0.5 --web                              # default chain (fast)
servicescan 10.0.0.5 --full                             # thorough chain (one flag)
servicescan 10.0.0.5 --web --web-render                 # default + JS rendering
servicescan 10.0.0.5 --web --web-depth 2 --web-max-pages 150   # deeper/wider crawl
servicescan 10.0.0.5 --web --write-hosts                # also persist cert SANs
servicescan 10.0.0.5 --full --web-depth 5               # full profile, depth tuned
```

What the flags do (all require, or imply, `--web`):

| Flag | Effect | Default |
|------|--------|---------|
| `--web` | run the chain: webrecon on every web port | HTTP-only, depth 1, 60 pages/port |
| `--full` | thorough preset, **implies `--web`**: JS render on, depth 3, 300 pages/port | off |
| `--web-render` | enable Playwright JS rendering (catches JS-injected links; slower, needs Chromium) | off (on under `--full`) |
| `--web-depth N` | crawl depth per web port | 1 (3 under `--full`) |
| `--web-max-pages N` | hard page cap per web port | 60 (300 under `--full`) |
| `--write-hosts` | also append harvested cert SANs -> IP to `/etc/hosts` | off |

`--full` is just a convenience profile: it sets render on and the deeper
depth/page limits so you do not have to spell them out. **Any `--web-*` flag you
pass still wins**, e.g. `--full --web-depth 5` keeps everything `--full` turns on
but uses depth 5.

`--write-hosts` is **not** needed for the crawl itself: the chain already reaches
cert-only names in-process (see below). It is only for persisting those names so
*other* tools (or a browser) resolve them afterwards, so it is opt-in and needs
root.

**The internal pivot.** On private networks crt.sh is empty, but the TLS
certificate on a scanned port usually names other internal hosts in its SANs,
and those names often exist *only* in the cert (an admin or staging vhost that
was never put in DNS). The chain harvests every SAN across all TLS ports, maps
each name to the scanned IP, and enumerates it against that IP with the right
`Host` header and TLS SNI. So a cert-only name such as `admin.corp.internal`
gets reached and crawled **without editing DNS or `/etc/hosts`**: the mapping is
in-process (`--write-hosts` is opt-in, for feeding other tools). The browser path
mirrors the same mapping via Chromium's `--host-resolver-rules`.

> **NVD rate limits:** without an API key NVD allows ~5 requests / 30s. Get a
> free key at <https://nvd.nist.gov/developers/request-an-api-key> and pass it
> via `--nvd-api-key` or the `NVD_API_KEY` env var for larger scans.

### Output — servicescan

Each run is filed under `<outdir>/<target>/<timestamp>/` with a `latest`
symlink (so re-scans never overwrite); `--flat` writes straight into `-o`
(default base `servicescan-out/`). Per run:

- `scan.json` — full results (services, versions, provenance, CVEs incl.
  `epss`, `epss_pct` and `kev` fields per CVE)
- `services.txt` — `port/proto  state  name  product version  [conf]  (sources)`
- `cves.txt` — `score  severity  CVE-ID  port/ident  epss=  KEV  source  url`
  (score-sorted)
- `nuclei-targets.txt` — every open **HTTP(S)** service as one `scheme://host:port`
  per line (hostname preferred over IP, TLS detected by name/cert/port), ready
  for `nuclei -l nuclei-targets.txt` (also fine for httpx / katana / feroxbuster)
- `nuclei-targets-net.txt` — every open **non-web** service as one `host:port`
  per line (no scheme), the form nuclei's network / ssl / javascript protocol
  templates expect (ssh, ftp, redis, mysql, jmx, distcc, ajp, …):
  `nuclei -l nuclei-targets-net.txt`. Both lists are written on every scan, no
  `--web` needed, and each open service lands in exactly one of them.
- with `--web`: a consolidated, scope-confined `urls-all.txt` / `params-all.txt`
  across every web port, plus per-port webrecon output under
  `web/<port>-<scheme>/` (`report.json`, `urls.txt`, `secrets.txt`, …); each
  service in `scan.json` also carries a compact `web` summary

The console prints each service with its merged version, provenance
(`nmap+http+banner`), and the top CVEs colored by severity — with an `EPSS %`
figure and a red `[KEV]` badge on anything in the CISA Known Exploited
Vulnerabilities catalog. Per service, KEV-listed CVEs are ranked first. It
closes with copy-pasteable `nuclei` commands for the web and non-web target
lists, written with absolute paths (and `2>/dev/null` to drop the Go
`net/http` idle-channel noise) so they run from any directory.

---

## Notes

- TLS verification is **off** by default for recon (`--verify-tls` to enable).
- Rendering spawns a browser context per page, so render-mode uses fewer
  workers; `--no-render` is much faster but misses JS-dynamic links.
- crt.sh and DNS resolution need outbound access; on restricted networks those
  phases may return empty.
- `servicescan` needs the `nmap` binary for full port coverage, and outbound
  HTTPS to `services.nvd.nist.gov` / `api.osv.dev` for CVE correlation, plus
  `api.first.org` (EPSS) and `cisa.gov` (KEV) for risk enrichment; all degrade
  gracefully (fingerprint-only / zero CVEs / no enrichment) when unavailable.

---

## Legal

For use **only** against systems you own or are explicitly authorized to test.
Unauthorized scanning is illegal and entirely your responsibility.

## Credits

The technology fingerprint catalog (`servicescan/data/tech_fingerprints.json`)
is generated by `scripts/build_tech_catalog.py` from
[projectdiscovery/wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)
(MIT, © 2021 ProjectDiscovery, Inc.), itself derived from the open-source
Wappalyzer ruleset. The snapshot keeps the CVE-correlatable apps (299) and
compiles each to the signals servicescan can match: header/meta/cookie/script/
HTML on a plain GET, plus JavaScript-global and DOM selectors evaluated on a
rendered page (`--render` / the `--web` crawl). Only a transformed snapshot is
vendored; there is no runtime dependency on that project.

## License

[MIT](LICENSE) © 2026 Kaya Emre Arıkan
