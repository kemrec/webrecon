"""Secret / credential scanner.

Scans response bodies (HTML + JS) for leaked secrets: API keys, tokens,
passwords, usernames, private keys, cloud creds, JWTs, DB connection strings,
and generic high-entropy assignments. Each finding is classified by type and
severity, with the full matched value and line/offset context.

Patterns draw on the gitleaks / truffleHog / secretfinder rule families
(provider-specific prefixes + generic assignment forms). Values are reported in
full and never redacted: this is an operator recon tool, the raw secret is the
actionable output.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    type: str
    severity: str          # high | medium | low
    match_preview: str     # the full matched secret value (not redacted)
    source: str            # url the secret was found in
    context: str           # short surrounding snippet
    line: int

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# High-confidence, provider-specific patterns (name, severity, regex).
# Anchored on vendor prefixes/shapes -> high signal, low false-positive.
# ---------------------------------------------------------------------------
_PROVIDER = [
    # --- cloud ---
    ("AWS Access Key ID",        "high",   r"\b(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS Secret Access Key",    "high",   r"(?i)aws(.{0,20})?(?:secret|sk)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("AWS MWS Auth Token",       "high",   r"\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    ("Google API Key",           "high",   r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("Google OAuth Token",       "high",   r"\bya29\.[0-9A-Za-z\-_]+"),
    ("Google OAuth Client ID",   "low",    r"\b[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com\b"),
    ("GCP Service Account",      "high",   r'"type":\s*"service_account"'),
    ("Firebase Cloud Msg Key",   "high",   r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b"),
    ("Azure Storage Key",        "high",   r"(?i)AccountKey=[A-Za-z0-9+/]{86}=="),
    ("DigitalOcean Token",       "high",   r"\bdo[portr]_v1_[a-f0-9]{64}\b"),
    ("HashiCorp Vault Token",    "high",   r"\bhv[sb]\.[A-Za-z0-9_\-]{24,}\b"),
    ("Terraform Cloud Token",    "high",   r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_=]{60,}\b"),
    # --- VCS / CI ---
    ("GitHub Token",             "high",   r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    ("GitHub Fine-grained PAT",  "high",   r"\bgithub_pat_[0-9A-Za-z_]{82}\b"),
    ("GitLab PAT",               "high",   r"\bglpat-[0-9A-Za-z\-_]{20}\b"),
    ("Atlassian API Token",      "high",   r"\bATATT3[A-Za-z0-9_\-=]{180,}\b"),
    ("Grafana Service Account",  "high",   r"\bglsa_[A-Za-z0-9]{32}_[a-f0-9]{8}\b"),
    ("Grafana Cloud Token",      "high",   r"\bglc_[A-Za-z0-9+/]{32,}={0,2}\b"),
    # --- payment ---
    ("Stripe Live Secret Key",   "high",   r"\b[sr]k_live_[0-9a-zA-Z]{24,}\b"),
    ("Stripe Test Secret Key",   "medium", r"\bsk_test_[0-9a-zA-Z]{24,}\b"),
    ("Stripe Publishable Key",   "low",    r"\bpk_live_[0-9a-zA-Z]{24,}\b"),
    ("Square Access Token",      "high",   r"\bsq0atp-[0-9A-Za-z\-_]{22}\b"),
    ("Square OAuth Secret",      "high",   r"\bsq0csp-[0-9A-Za-z\-_]{43}\b"),
    ("PayPal Braintree Token",   "high",   r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b"),
    # --- comms / messaging ---
    ("Slack Token",              "high",   r"\bxox[baprse]-[0-9A-Za-z\-]{10,48}\b"),
    ("Slack App Token",          "high",   r"\bxapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+\b"),
    ("Slack Webhook",            "high",   r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    ("Discord Bot Token",        "medium", r"\b[MNO][A-Za-z\d_\-]{23}\.[\w\-]{6}\.[\w\-]{27,38}\b"),
    ("Discord Webhook",          "high",   r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+"),
    ("Telegram Bot Token",       "medium", r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
    ("Twilio Account SID",       "medium", r"\bAC[0-9a-fA-F]{32}\b"),
    ("Twilio API Key",           "high",   r"\bSK[0-9a-fA-F]{32}\b"),
    ("SendGrid API Key",         "high",   r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b"),
    ("Mailgun API Key",          "high",   r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("Mailchimp API Key",        "high",   r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"),
    ("Postmark Server Token",    "medium", r"(?i)postmark[._-]?(?:server|api)[._-]?token['\"]?\s*[:=]\s*['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"),
    # --- package registries ---
    ("npm Token",                "high",   r"\bnpm_[0-9A-Za-z]{36}\b"),
    ("PyPI Upload Token",        "high",   r"\bpypi-AgEIcHlwaS[A-Za-z0-9\-_]{50,}\b"),
    # --- AI / LLM ---
    ("OpenAI API Key",           "high",   r"\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}T3BlbkFJ[A-Za-z0-9\-_]{20,}\b"),
    ("Anthropic API Key",        "high",   r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
    ("HuggingFace Token",        "high",   r"\bhf_[A-Za-z0-9]{34}\b"),
    # --- SaaS / misc ---
    ("Heroku API Key",           "medium", r"(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"),
    ("Datadog API Key",          "medium", r"(?i)dd[-_]?api[-_]?key(.{0,20})?['\"][0-9a-f]{32}['\"]"),
    ("New Relic API Key",        "high",   r"\bNRAK-[A-Z0-9]{27}\b"),
    ("New Relic User Key",       "high",   r"\bNRAA-[a-f0-9]{27}\b"),
    ("Postman API Key",          "high",   r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"),
    ("Databricks Token",         "high",   r"\bdapi[a-f0-9]{32}\b"),
    ("Linear API Key",           "high",   r"\blin_api_[A-Za-z0-9]{40}\b"),
    ("Notion Integration Token", "high",   r"\bntn_[A-Za-z0-9]{36,}\b"),
    ("Shopify Access Token",     "high",   r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),
    ("Dropbox Token",            "high",   r"\bsl\.[A-Za-z0-9_\-]{130,}\b"),
    ("Mapbox Secret Token",      "high",   r"\bsk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    ("Sentry DSN (secret)",      "medium", r"\bhttps://[0-9a-f]{32}:[0-9a-f]{32}@[a-z0-9.\-]+/[0-9]+\b"),
    ("Facebook Access Token",    "medium", r"\bEAA[A-Za-z0-9]{90,}\b"),
    # --- generic high-value shapes ---
    ("JWT",                      "medium", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("Private Key Block",        "high",   r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ("Basic Auth in URL",        "high",   r"https?://[A-Za-z0-9._%+\-]+:[^@\s/'\"]+@[A-Za-z0-9.\-]+"),
    ("Authorization Basic",      "medium", r"(?i)authorization['\"]?\s*[:=]\s*['\"]?basic\s+[A-Za-z0-9+/]{16,}={0,2}"),
    ("DB Connection String",     "high",   r"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'\"]+:[^\s'\"@]+@[^\s'\"]+"),
    ("Authorization Bearer",     "medium", r"(?i)authorization['\"]?\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9\-._~+/]{16,}"),
]

# ---------------------------------------------------------------------------
# Generic assignment patterns: key-name on the left, secret-ish value on right.
# These are noisier -> medium/low, with entropy gating.
# ---------------------------------------------------------------------------
_KEYWORDS = (
    r"passwd|password|pwd|pass|secret|token|apikey|api[_-]?key|access[_-]?key|"
    r"auth[_-]?token|client[_-]?secret|private[_-]?key|session|credential|"
    r"bearer|x[-_]api[-_]key|username|user[_-]?name|login|db[_-]?pass|"
    r"encryption[_-]?key|signing[_-]?key|refresh[_-]?token|secret[_-]?key"
)
_GENERIC_ASSIGN = re.compile(
    rf"""(?i)\b({_KEYWORDS})\b\s*[:=]\s*['"`]([^'"`\s]{{4,200}})['"`]"""
)

# username-ish (lower severity, informational)
_USERNAME_HINT = re.compile(
    r"""(?i)\b(?:user(?:name)?|login|email|e-mail)\b\s*[:=]\s*['"`]([^'"`\s]{3,80})['"`]"""
)

# Aggressive (opt-in) entropy sweep: any quoted string literal that *looks*
# like a secret by shape + entropy, regardless of the left-hand key name -- the
# gitleaks "generic-api-key" idea. This catches keys assigned to oddly-named
# variables the keyword list misses, at the cost of noise (content hashes,
# minified identifiers, nonces, build IDs), so it is off by default and only
# ever rated low. Candidate literals are 20-100 base64 / hex / url-safe chars.
_ENTROPY_LITERAL = re.compile(r"""['"`]([A-Za-z0-9][A-Za-z0-9+/=_\-]{19,99})['"`]""")
# pure hex of a common digest length -> almost always an integrity/content
# hash, an etag or a build fingerprint, not a credential.
_HEX_DIGEST = re.compile(r"(?i)\A(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})\Z")
_ENTROPY_MIN = 4.0

_PLACEHOLDER_VALUES = {
    "password", "changeme", "example", "your_password", "yourpassword",
    "xxxxxxxx", "null", "none", "true", "false", "undefined", "test",
    "placeholder", "secret", "token", "apikey", "value", "string",
    "<password>", "***", "redacted", "dummy", "foobar", "your-api-key",
    "yourapikey", "your_token", "youremail", "your_email", "username",
    "user", "admin", "email", "process.env", "import.meta.env",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _snippet(text: str, start: int, end: int) -> str:
    """A short, single-line slice of the surrounding source for context. The
    secret itself is shown verbatim (match_preview carries the full value)."""
    a = max(0, start - 30)
    b = min(len(text), end + 10)
    frag = text[a:b].replace("\n", " ").replace("\r", " ")
    return frag[:200]


def scan(text: str, source: str, aggressive: bool = False) -> list[Finding]:
    """Scan one blob of text; return list of Findings.

    With aggressive=True, additionally run an entropy-first sweep for
    secret-shaped string literals whose surrounding key name is not one we
    recognise (gitleaks "generic-api-key"). Noisy and low-severity: opt-in.
    """
    if not text:
        return []
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    values_seen: set[str] = set()            # values already reported (any type)

    def add(ftype, sev, value, start, end):
        key = (ftype, value[:60])
        if key in seen:
            return
        seen.add(key)
        values_seen.add(value[:60])
        findings.append(Finding(
            type=ftype, severity=sev,
            match_preview=value,                 # full value, not redacted
            source=source,
            context=_snippet(text, start, end),
            line=_line_of(text, start),
        ))

    # provider-specific
    for name, sev, pat in _PROVIDER:
        for m in re.finditer(pat, text):
            full = m.group(0)
            add(name, sev, full, m.start(), m.end())

    # generic key=value secrets
    for m in _GENERIC_ASSIGN.finditer(text):
        keyword = m.group(1).lower()
        value = m.group(2)
        if value.lower() in _PLACEHOLDER_VALUES:
            continue
        if re.fullmatch(r"[\d.]+", value):            # version/number
            continue
        if value.startswith(("http", "/", "./", "#", "{{", "$", "%")):  # url/template
            continue
        ent = _shannon_entropy(value)
        is_user_field = keyword in ("username", "user_name", "user-name", "login")
        if is_user_field:
            add("Username/Login", "low", value, m.start(), m.end())
            continue
        # password/token/secret: keep if long-ish or high entropy
        if len(value) >= 8 or ent >= 3.0:
            sev = "high" if ("secret" in keyword or "password" in keyword
                             or "pwd" in keyword or "token" in keyword
                             or "key" in keyword) else "medium"
            add(f"Generic secret ({keyword})", sev, value, m.start(), m.end())

    # standalone username hints (info only, dedup with above)
    for m in _USERNAME_HINT.finditer(text):
        value = m.group(1)
        if value.lower() in _PLACEHOLDER_VALUES:
            continue
        add("Username/Email hint", "low", value, m.start(), m.end())

    # aggressive entropy sweep (opt-in): secret-shaped literals the keyword
    # passes above did not already catch. Deliberately conservative to keep the
    # noise bounded: needs mixed letters+digits, real character variety, high
    # Shannon entropy, and must not be a plain content-hash digest.
    if aggressive:
        for m in _ENTROPY_LITERAL.finditer(text):
            value = m.group(1)
            if value[:60] in values_seen:                 # already reported
                continue
            if value.lower() in _PLACEHOLDER_VALUES:
                continue
            if _HEX_DIGEST.match(value):                   # md5/sha/etag hash
                continue
            if not (any(c.isdigit() for c in value)
                    and any(c.isalpha() for c in value)):  # need both classes
                continue
            if len(set(value)) < max(10, len(value) // 2):  # too repetitive
                continue
            if _shannon_entropy(value) < _ENTROPY_MIN:
                continue
            add("High-entropy string (aggressive)", "low",
                value, m.start(1), m.end(1))

    return findings
