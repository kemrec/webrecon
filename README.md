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

By default the human-facing reports (console, `cves.txt`, CSV, HTML) focus on
the findings worth acting on first: CVEs in **CISA KEV** or rated
**HIGH/CRITICAL** (CVSS ≥ 7.0). This keeps a long tail of medium/low CVEs on
old products from burying the serious ones, and the console notes how many were
hidden. Nothing is lost — `scan.json` always records the **complete** CVE set
(medium and low included); pass `--all-cves` to show everything in the reports
too.

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
  identical recon over a TLS transport, and additionally grabs the TLS
  certificate: its subject CN / SAN names (often internal-only hostnames that
  exist nowhere else) are stored on the service and harvested by the `--web`
  chain as cert-only vhost candidates mapped to the scanned IP — the same SAN
  pivot the HTTPS ports already feed. Nothing is ever `PLAY`ed or recorded.
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
  `GetServices`. When the device advertises a **PTZ** service, `GetConfigurations`
  confirms the camera is motorized (an attacker with this access can aim it —
  `ContinuousMove`/`AbsoluteMove`/`GotoPreset` — to look away or track); when it
  advertises an **events** service, `GetEventProperties` lists the topic set
  (motion/tamper/analytics/I/O) a client could subscribe to. PTZ/events are
  claimed only when `GetServices` actually lists them, so a fixed camera never
  produces a false positive. Read-only SOAP calls only — no move is ever issued.
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
- **SSDP / UPnP** (UDP 1900): a unicast `M-SEARCH` (`ssdp:all`) makes a UPnP
  device answer with its `SERVER` string, the `LOCATION` of its device
  description, and the `ST`/`USN` of each advertised target; the description XML
  is then fetched read-only (keeping the scanned host — the advertised LAN IP is
  never followed) to recover manufacturer/model/firmware and the list of UPnP
  services. UPnP discovery is unauthenticated **by design**, so this is reported
  **informationally** (`ssdp-upnp`) — device enumeration for CVE anchoring and
  attack-surface mapping, not an unauth-access alert. An advertised Internet
  Gateway control service (`WANIPConnection`/`WANPPPConnection`) is flagged as a
  hardening concern. Run once per host, unicast only.
- **Vendor camera CGI** (camera-signalled web port): the HTTP management API that
  Hikvision (`/ISAPI/System/deviceInfo`), Dahua (`/cgi-bin/magicBox.cgi`) and Axis
  (`/axis-cgi/param.cgi`) cameras expose beside RTSP/ONVIF. A read-only `GET` that
  returns device info **without credentials** is a **critical** misconfiguration
  (the CVE-2017-7921 ISAPI class); a `401` is probed with a tiny default-credential
  list over HTTP Basic/Digest, and an accepted default (model + firmware recovered,
  fed to CVE correlation) is **critical**. The cred test is self-limiting — a path
  the device doesn't implement `404`s, so defaults are only tried against the API
  the device actually speaks — and is governed by the same `--no-cam-creds` switch.
- **Vendor private binary protocols** (device-management control channels, read-only
  detection): **Dahua DVRIP/DHIP** (TCP 37777) — sends the *pre-auth realm request*
  (no credentials, no login completed; just the step that asks the device for its
  login challenge) and confirms the DVRIP/DHIP response, recovering the realm
  string (which often carries the device serial); **Hikvision SDK / HCNetSDK**
  (TCP 8000) — the device greets on connect with a fixed 16-byte handshake, so the
  probe sends *nothing* and reads it (the nmap “Hikvision IPCam control port”
  signature). Both ports are auth-gated for actual control, so a hit is reported
  as an informational device identification (and a CVE anchor for Dahua/Hikvision
  — e.g. the CVE-2021-33044/33045 and CVE-2017-7921 classes), not an
  unauthenticated-access alert. 8000 is shared with HTTP/ONVIF, so a non-SDK
  service there falls through to the ONVIF/web checks.
- **Camera WebSocket video preview** (Hikvision `ws` 7681 / `wss` 7682, and any
  camera-signalled port — it can sit on 81 etc.): the plugin-free web live-view
  ships video over a WebSocket that is *meant* to be session/token
  authenticated, so the finding is a device that streams **without** credentials.
  The probe does a standard RFC6455 upgrade with **no auth** and then only
  **reads what the device volunteers** — no `PLAY`/start command, no exploit. If
  the device pushes **binary video frames unauthenticated**, that is an anonymous
  live feed anyone can watch in a browser (**critical**, `camera-ws-stream-unauth`).
  If the upgrade is accepted but no frames arrive without an explicit start, the
  endpoint is reported informationally (reachable, upgrade unauthenticated;
  anonymous playback *not* claimed — a device needing an in-band token won't
  stream here); a refused upgrade (401/403) is noted as auth-enforced. The alert
  fires only on observed unauthenticated video bytes, never on a guessed stream.
- **ttyd web terminal** (shares the camera default `7681`, `7682` for `wss`, or a
  `ttyd`-named service): `ttyd` serves an interactive shell in the browser, so an
  instance with no authentication is a **browser shell = remote code execution** —
  checked **before** the camera WebSocket probe so the two are never confused.
  Detection stays strictly on the HTTP layer (`GET /`, `GET /token`, and the
  `WWW-Authenticate: Basic realm="ttyd"` signature) and **never opens the `/ws`
  shell socket** or spawns a PTY. An unauthenticated instance (page/token served
  with no credentials) is **critical**, `ttyd-shell-unauth`; one that demands
  Basic auth (`ttyd -c`) is reported informationally as auth-enforced
  (`ttyd-shell-auth`, not an alert).
- **gRPC / HTTP2** (dedicated gRPC ports — 50051/6565/9090/… — or a `grpc`-named
  service): dependency-free detection (TLS ALPN `h2`, or the cleartext h2c
  preface → SETTINGS frame). The real finding is **server reflection enabled
  without authentication**, which lets anyone enumerate every service (the gRPC
  analogue of an open Swagger) — reported as critical with the service list. The
  reflection `list_services` call is done **natively, with no dependency**: the
  service names come back in the response DATA frame (protobuf), not the HPACK
  headers, so only HPACK *encoding* (literals, no Huffman) plus a tiny protobuf
  reader are needed — no gRPC library. `grpcurl`/`grpcio` are used only as an
  optional fallback if the native client can't complete the exchange. When
  reflection is open, it then drills into the **method surface** natively via
  `file_containing_symbol`: the returned `FileDescriptorProto` is parsed (package
  + `ServiceDescriptorProto` → `MethodDescriptorProto`) to list the exact RPC
  method names per service — the call surface a client needs to invoke them
  without a `.proto`. Bounded to a capped number of symbols so a large surface
  can't fan out into unbounded connections. Scoped to gRPC ports so HTTPS/2 web
  ports are never mislabelled. Read-only (list/describe only).
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
- **MQTT** (TCP `1883`, `8883` over TLS): a dependency-free, hand-rolled MQTT
  3.1.1 **anonymous** `CONNECT` (no username/password). A broker that answers
  `CONNACK 0x00` accepts unauthenticated clients — anyone who can reach it can
  subscribe to `#` to read every published message and publish to any topic,
  which on IoT/OT deployments means reading telemetry and issuing device
  commands (**critical**, `mqtt-unauth`). A refusal for credentials (`0x04`/
  `0x05`) is reported informationally as auth-enforced (`mqtt-auth`), and a
  refusal for another reason as detected-only (`mqtt-detected`); neither is an
  alert. On an anonymous accept the probe additionally subscribes to the single
  `$SYS/broker/version` metadata topic to recover a broker version for CVE
  matching — **never an application topic**, and it publishes nothing.
- **SMB** (TCP `445`): dependency-free internal-network triage with no
  credentials. A hand-rolled SMB2 negotiate reads the **signing posture** — a
  host where signing is *not required* can be **NTLM-relayed** (ntlmrelayx) to
  run commands or pivot without a password (**alert**, `smb-signing-not-required`).
  A separate SMB1 `NT LM 0.12` negotiate detects **SMBv1 enabled** — the
  EternalBlue / MS17-010 wormable-RCE surface (**alert**, `smbv1-enabled`).
  Finally an anonymous SMB2 session-setup sends only an NTLM `NEGOTIATE`
  (type 1) and **reads the server's `CHALLENGE`** (type 2) — no credentials,
  no type-3, so no authentication is attempted — which discloses the host's OS
  build and AD/NetBIOS domain and computer names in a single unauthenticated
  packet (`smb-ntlm-info`, informational recon that also anchors CVE
  correlation to the Windows build). Signing *required* is reported as good
  posture.
- **NTLM over HTTP** (any web port): IIS/Exchange/RDWeb endpoints that offer
  `WWW-Authenticate: NTLM`/`Negotiate` leak the same host identity as SMB. A
  `GET` carrying only an NTLM `NEGOTIATE` (no credentials) makes the server
  answer `401` with an NTLM `CHALLENGE` naming the OS build and AD/NetBIOS
  domain and computer — reported informationally (`http-ntlm-info`, also
  anchoring CVE correlation). `/` is always checked; the Exchange/RDWeb paths
  (`/ews/`, `/rpc/`, `/autodiscover/…`, `/RDWeb/`, …) are swept only when the
  server banner looks like Microsoft-IIS, so generic web ports cost one request.
- **NFS / rpcbind** (TCP `111`): dependency-free ONC RPC. A portmap `DUMP`
  enumerates the registered RPC programs (NFS/NIS/quota/lock — `rpcbind-dump`,
  informational attack-surface map), and when `mountd` is present its `EXPORT`
  procedure lists the NFS exports and the hosts each is shared with
  (`nfs-exports`). An export shared with **everyone** (empty group list or `*`)
  is reachable by any client — mountable and readable, and with `no_root_squash`
  writable as root — a **world-readable export alert** (`nfs-export-world`). All
  calls are read-only query procedures; nothing is mounted.
- **LDAP** (TCP `389`, `636` over TLS): dependency-free BER. An **anonymous
  simple bind** (empty DN + password) that succeeds, followed by a rootDSE read,
  is AD recon — it names the naming contexts (domain DN), the DC hostname and
  the forest/domain functional levels (`ldap-rootdse`, informational; also sets
  the product to Active Directory). The **alert** is when an anonymous
  one-level search of a naming context actually returns directory objects:
  anonymous directory reads are enabled, so anyone can enumerate users, groups
  and computers without credentials — a prime password-spray / Kerberoast
  target list (`ldap-anonymous-read`). A refused anonymous bind is noted as good
  posture. All operations are reads.
- **rsync daemon** (TCP `873`): the daemon's module listing is read without
  authentication (`rsync-modules`, informational). Selecting the first module
  then shows whether it demands credentials: a module that answers `@RSYNCD: OK`
  (no `AUTHREQD`) accepts **anonymous access** — anyone who can reach `873` can
  read its files, and write to them if the module is not read-only (**alert**,
  `rsync-anon-module`). Protocol 29 is negotiated so no digest list is needed,
  and no rsync options are sent after `OK`, so no file transfer occurs.
- **WinRM / WS-Management** (TCP `5985` HTTP, `5986` HTTPS, endpoint `/wsman`):
  dependency-free, no credentials are ever sent. An unauthenticated WS-Management
  **Identify** (MS-WSMV `<wsmid:Identify/>`) confirms the service and leaks the
  vendor + WSMan stack version (`winrm-identify`, informational; the OS build is
  withheld in the unauthenticated response by design). The offered auth schemes
  are read from the `401` challenge (`winrm-auth-methods`), and when `Negotiate`
  is offered the NTLM type-2 challenge on `/wsman` discloses the host OS build +
  AD/NetBIOS identity (`winrm-ntlm-info`, informational recon). The **alert** is
  `Basic` offered over **plaintext** `5985` (`AllowUnencrypted`): credentials are
  sent base64-encoded with no transport encryption, so any on-path observer
  captures them and a valid WinRM credential grants remote PowerShell = host
  takeover (`winrm-basic-cleartext`). `Basic` over TLS (`5986`) is informational
  (`winrm-basic-tls`). All operations are reads.
- **PostgreSQL** (TCP `5432`): a dependency-free protocol-3.0 StartupMessage with
  no password makes the backend declare its authentication method without a
  credential ever being sent. `AuthenticationOk` means `pg_hba.conf` matched
  **`trust`** — any client that can reach the port gets a full read/write session
  (and, via `COPY`/large-objects or an untrusted PL, often code execution on the
  host): a **trust/unauthenticated alert** (`postgres-trust-unauth`, with the
  leaked `server_version`). A password/MD5/SCRAM challenge or an `ErrorResponse`
  means auth is enforced (`postgres-auth`, informational; a cleartext-password
  demand is flagged). No query is ever issued — the session is dropped at
  `AuthenticationOk`.
- **MySQL / MariaDB** (TCP `3306`): the server sends its `HandshakeV10` greeting
  the instant the socket opens, so reading it — **nothing is ever sent** — leaks
  the server version (a CVE anchor), the default auth plugin and the TLS
  capability (`CLIENT_SSL`). Reported informationally (`mysql-handshake`); a
  server that does not advertise TLS is flagged (clients not forcing SSL would
  send credentials in cleartext). No login is attempted.
- **Microsoft SQL Server** (TCP `1433` + UDP `1434`): two dependency-free,
  unauthenticated leaks. A **TDS `PRELOGIN`** (MS-TDS) on 1433 returns the server
  version and its encryption posture without a login (`mssql-prelogin`; an
  instance offering no TLS — `ENCRYPT_NOT_SUP` — is flagged, since login
  credentials would then be cleartext). The **SQL Server Browser** on UDP 1434
  (MC-SQLR) answers a single datagram with every instance's name, version and TCP
  port (`mssql-browser`). Informational; no login is ever sent.
- **RDP** (TCP `3389`): an X.224 Connection Request with an RDP Negotiation
  Request (`PROTOCOL_SSL|PROTOCOL_HYBRID`) makes the server reveal its negotiated
  security without authenticating. `HYBRID`/`HYBRID_EX` (or an
  `HYBRID_REQUIRED_BY_SERVER` failure) means **NLA/CredSSP is enforced** — good
  posture; `SSL`-only, standard RDP security, or a legacy no-negotiation reply
  means **NLA is not enforced**, which is flagged (`rdp-nla`, informational): the
  server accepts pre-authentication connections, widening exposure to
  credential-capture and BlueKeep-class pre-auth RCE. Dependency-free per
  MS-RDPBCGR; no credentials are sent.
- **VNC / RFB** (TCP `5900`-`5903`): after the RFB version handshake the server
  lists the security types it will accept. Security type **`None` (1)** means the
  server grants a full remote-desktop session with **no authentication** — anyone
  who can reach the port gets keyboard/mouse/screen control: an **alert**
  (`vnc-none-auth`; the offered types are also listed via `vnc-security-types`).
  The probe only reads the offered types per RFC 6143 — it never selects one, so
  no session is taken.
- **FTP** (TCP `21`): the `220` greeting leaks the server banner, then
  `USER anonymous` / `PASS` tells whether **anonymous login** is allowed
  (`230` → `ftp-anon` alert) or refused (good posture). Anonymous login uses no
  real credential (same model as the LDAP/rsync anonymous checks); no listing or
  transfer is performed — the session is closed with `QUIT` right after the login
  result.
- **MSRPC endpoint mapper** (TCP `135`): an unauthenticated DCE/RPC bind to the
  IOXIDResolver interface followed by **`ServerAlive2`** (opnum 5) returns a
  `DUALSTRINGARRAY` naming every one of the host's network interface bindings —
  hostnames and IPv4/IPv6 addresses, including internal ones — with no credential
  (`msrpc-interfaces`, an informational topology leak like the NTLM-over-HTTP
  disclosure). The string bindings are extracted from the response; PDU layout
  per MS-RPCE, `ServerAlive2` per MS-DCOM. No credentials are sent.
- **Kerberos KDC** (TCP `88`): dependency-free ASN.1/DER per RFC 4120. For a
  small built-in set of default principals an **AS-REQ with no pre-authentication**
  is sent; the KDC's reply classifies each account without ever sending a
  credential — `KDC_ERR_PREAUTH_REQUIRED` (25) or an AS-REP means the user
  **exists**, `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6) means it does not
  (`krb-user-enum`, informational; Kerberos pre-auth leaks username validity to
  anyone who can reach `88`). The **alert** is an account whose pre-auth is
  **disabled**: the KDC returns an AS-REP to the unauthenticated request, and its
  enc-part — encrypted with the account's key — is crackable offline, i.e. a
  credential obtained with no prior access (**AS-REP roasting**,
  `krb-asrep-roastable`; the hashcat-`18200` `$krb5asrep$` hash is emitted as
  proof for RC4). A **realm is mandatory** in the AS-REQ: supply it with
  `--realm`/`--domain`, or it is derived from a dotted-FQDN target
  (`dc01.corp.local` → `CORP.LOCAL`); a bare-IP target with no `--realm` skips
  the check. Only the unauthenticated AS-REQ is ever sent.

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
servicescan host --all-cves               # show every CVE in reports (default focuses on KEV/HIGH/CRITICAL; scan.json always keeps all)
servicescan 10.0.0.5 --no-cam-creds       # camera recon (RTSP+ONVIF) read-only, no default-cred test
servicescan dc01.corp.local               # realm CORP.LOCAL auto-derived for the Kerberos (88) check
servicescan 10.0.0.5 --realm CORP.LOCAL   # bare-IP DC: supply the realm for AS-REP-roast / user enum
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
`--no-nmap`, `--udp`, `--nse`, `--nse-scripts`, `--fp-all`, `--render`, `--no-cam-creds`, `--realm/--domain`, `--no-cve`,
`--no-nvd`, `--no-osv`, `--no-epss`, `--no-kev`, `--exploits`, `--nvd-api-key`,
`--min-cvss`, `--all-cves`, `--kev-high`, `--no-cache`, `--cache-ttl`, `--web`, `--full`, `--web-render`,
`--web-depth`, `--web-max-pages`, `--write-hosts`, `-c/--concurrency`,
`-t/--timeout`, `-o/--outdir`. Full list: `servicescan -h`.

Every scan writes, alongside `scan.json`: `services.txt`, `cves.txt`,
`services.csv`, `cves.csv`, `scan.jsonl` (one service per line), two nuclei
target lists (`nuclei-targets.txt` = web `scheme://host:port`, and
`nuclei-targets-net.txt` = non-web `host:port` for network/ssl templates), and a
standalone `report.html` (summary cards + per-host service/CVE tables with CVSS
colouring and KEV/exploit badges), and `scan.sarif` (SARIF 2.1.0). `scripts.txt`
is added when `--nse` ran.

`scan.sarif` is for CI / GitHub code-scanning ingestion: every CVE and every
unauthenticated-exposure alert becomes a SARIF result, located by a
`host:port/proto` locator, with the rule's `security-severity` taken from the
CVSS score (so GitHub ranks them correctly) and a stable `partialFingerprint`
per `host:port:rule` for cross-run de-duplication. Informational scripts
(enumeration detail) are not emitted — only actionable findings.

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
- `scan.sarif` — SARIF 2.1.0 for CI / GitHub code scanning: each CVE and each
  unauthenticated-exposure alert as a result, `security-severity` from CVSS,
  `host:port/proto` locator, stable per-finding `partialFingerprints`
- `services.csv` / `cves.csv` / `scan.jsonl` — spreadsheet / line-oriented views
- `report.html` — standalone summary (cards + per-host service/CVE tables)
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

## Web UI (`webrecon_ui`)

A minimal, **dependency-free** local console for servicescan, built on the
standard-library `http.server` (no FastAPI/Flask, no npm). The scan engine, CVE
correlation and exposure/SARIF logic are reused unchanged; this is only a thin
HTTP layer that maps a JSON request to a `ScanConfig`, runs one scan, and
returns the result.

```bash
# start the console (binds 127.0.0.1 by default), then open the URL
python -m webrecon_ui                 # http://127.0.0.1:8787
python -m webrecon_ui --port 9000
```

Opening `http://127.0.0.1:8787/` serves a single, self-contained **vanilla
HTML/JS page** (no framework, no build step): a target + options form, a
per-host service table with CVEs, unauthenticated-exposure findings highlighted
in red (the page pulls the alert-id list from `/api/alert-ids` so it never
drifts from the engine), and a **Download** control with a format picker
(scan.json, SARIF, CSV, JSONL, HTML report, nuclei target lists, …). Scans run
**live** over SSE, so each host appears as it finishes rather than after the
whole scan.

It binds to **localhost** on purpose: the API launches scans against whatever
target the caller names, so it must not be reachable by untrusted clients. A
non-loopback `--host` prints a warning.

API:

- `GET  /` → the operator console (static HTML page)
- `GET  /api/health` → `{"ok": true, "service": "webrecon-ui"}`
- `GET  /api/alert-ids` → the set of script ids that are unauthenticated-breach
  alerts (vs informational), for the page's exposure highlighting
- `POST /api/scan` → `scan.json`-shaped result plus a `scan_id`
- `GET  /api/scan/stream?<opts>` → a **Server-Sent Events** stream of scan
  milestones (`start` with the host count, a `host` event as each host's
  fingerprint/exposure/CVE work finishes, a final `done` carrying the
  `scan_id`). Config comes from the query string, through the same allowlist.
  The page uses this so hosts render live instead of all at once at the end.
- `POST /api/scan.sarif` → SARIF 2.1.0 document (same as `scan.sarif`)
- `GET  /api/export/<scan_id>/<fmt>` → one output file for that scan, as a
  download. `<fmt>` is one of `json`, `sarif`, `services-csv`, `cves-csv`,
  `jsonl`, `html`, `nuclei-web`, `nuclei-net`, `services-txt`, `cves-txt`

So the console offers **every servicescan output format** (not just JSON/SARIF):
each completed scan is cached server-side under its `scan_id`, and an export is
rendered from that same scan via `report.write_all` (reusing every existing
writer verbatim — no re-scan, no duplicated formatting logic). The cache is a
small bounded LRU, fitting the single-operator, localhost nature of the tool.

The POST body is a JSON object (the SSE endpoint takes the same keys as query
params). Only an allowlisted subset of options is honoured — `target`
(required; string or list), `ports`, `use_nmap`, `top_ports`, `udp`, `nse`,
`nse_scripts`, `fingerprint`, `fp_all`, `render`, `cam_creds`, `realm`, `scan_rate`, `cve`,
the per-feed CVE sources `nvd` / `osv` / `epss` / `kev`, `nvd_api_key`, `min_cvss`,
`kev_high_only`, `exploits`, `timeout`, `concurrency`, and the `--web` crawl
chain (`web`, `web_render`, `web_depth`, `web_max_pages`). These are all scan
*semantics*; host-filesystem / subprocess-path knobs (`nmap_path`, `nmap_args`,
`outdir`) are deliberately **not** reachable from the web surface. With the web
chain enabled, each web port's crawl summary (pages / urls / params / secrets /
tech) is shown inline on the service and the crawl output is written under
`servicescan-out/` as usual.

```bash
curl -s -XPOST http://127.0.0.1:8787/api/scan \
  -d '{"target":"10.0.0.5","fp_all":true,"min_cvss":7.0}' | jq .
```

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
