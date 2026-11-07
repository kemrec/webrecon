"""Secret / credential scanner.

Scans response bodies (HTML + JS) for leaked secrets: API keys, tokens,
passwords, usernames, private keys, cloud creds, JWTs, DB connection strings,
and generic high-entropy assignments. Each finding is classified by type and
severity, with a redacted preview and line/offset context.

Patterns draw on the well-known gitleaks / truffleHog / secretfinder rule
families (provider-specific prefixes + generic assignment forms).
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    type: str
    severity: str          # high | medium | low
    match_preview: str     # redacted
    source: str            # url the secret was found in
    context: str           # short surrounding snippet (redacted)
    line: int

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# High-confidence, provider-specific patterns (name, severity, regex)
# ---------------------------------------------------------------------------
_PROVIDER = [
    ("AWS Access Key ID",        "high",   r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS Secret Access Key",    "high",   r"(?i)aws(.{0,20})?(?:secret|sk)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("Google API Key",           "high",   r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("Google OAuth Token",       "high",   r"\bya29\.[0-9A-Za-z\-_]+"),
    ("GCP Service Account",      "high",   r'"type":\s*"service_account"'),
    ("Firebase Cloud Msg Key",   "high",   r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b"),
    ("GitHub Token",             "high",   r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    ("GitHub Fine-grained PAT",  "high",   r"\bgithub_pat_[0-9A-Za-z_]{82}\b"),
    ("GitLab PAT",               "high",   r"\bglpat-[0-9A-Za-z\-_]{20}\b"),
    ("Slack Token",              "high",   r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b"),
    ("Slack Webhook",            "high",   r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    ("Stripe Live Secret Key",   "high",   r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    ("Stripe Restricted Key",    "high",   r"\brk_live_[0-9a-zA-Z]{24,}\b"),
    ("Stripe Publishable Key",   "low",    r"\bpk_live_[0-9a-zA-Z]{24,}\b"),
    ("Square Access Token",      "high",   r"\bsq0atp-[0-9A-Za-z\-_]{22}\b"),
    ("PayPal Braintree Token",   "high",   r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b"),
    ("Twilio API Key",           "high",   r"\bSK[0-9a-fA-F]{32}\b"),
    ("SendGrid API Key",         "high",   r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b"),
    ("Mailgun API Key",          "high",   r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("Mailchimp API Key",        "high",   r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"),
    ("npm Token",                "high",   r"\bnpm_[0-9A-Za-z]{36}\b"),
    ("OpenAI API Key",           "high",   r"\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}T3BlbkFJ[A-Za-z0-9\-_]{20,}\b"),
    ("Anthropic API Key",        "high",   r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
    ("Heroku API Key",           "medium", r"(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"),
    ("Datadog API Key",          "medium", r"(?i)dd[-_]?api[-_]?key(.{0,20})?['\"][0-9a-f]{32}['\"]"),
    ("JWT",                      "medium", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("Private Key Block",        "high",   r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("Basic Auth in URL",        "high",   r"https?://[A-Za-z0-9._%+\-]+:[^@\s/'\"]+@[A-Za-z0-9.\-]+"),
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
    r"bearer|x[-_]api[-_]key|username|user[_-]?name|login|db[_-]?pass"
)
_GENERIC_ASSIGN = re.compile(
    rf"""(?i)\b({_KEYWORDS})\b\s*[:=]\s*['"`]([^'"`\s]{{4,120}})['"`]"""
)

# username-ish (lower severity, informational)
_USERNAME_HINT = re.compile(
    r"""(?i)\b(?:user(?:name)?|login|email|e-mail)\b\s*[:=]\s*['"`]([^'"`\s]{3,80})['"`]"""
)

_PLACEHOLDER_VALUES = {
    "password", "changeme", "example", "your_password", "yourpassword",
    "xxxxxxxx", "null", "none", "true", "false", "undefined", "test",
    "placeholder", "secret", "token", "apikey", "value", "string",
    "<password>", "***", "redacted", "dummy", "foobar",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact(value: str) -> str:
    if len(value) <= 8:
        return value[0] + "***"
    return value[:4] + "***" + value[-2:]


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _snippet(text: str, start: int, end: int, secret: str) -> str:
    a = max(0, start - 30)
    b = min(len(text), end + 10)
    frag = text[a:b].replace("\n", " ").replace("\r", " ")
    return frag.replace(secret, _redact(secret))[:160]


def scan(text: str, source: str) -> list[Finding]:
    """Scan one blob of text; return list of Findings."""
    if not text:
        return []
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(ftype, sev, raw_match, value, start, end):
        key = (ftype, value[:40])
        if key in seen:
            return
        seen.add(key)
        findings.append(Finding(
            type=ftype, severity=sev,
            match_preview=_redact(value),
            source=source,
            context=_snippet(text, start, end, value),
            line=_line_of(text, start),
        ))

    # provider-specific
    for name, sev, pat in _PROVIDER:
        for m in re.finditer(pat, text):
            full = m.group(0)
            add(name, sev, full, full, m.start(), m.end())

    # generic key=value secrets
    for m in _GENERIC_ASSIGN.finditer(text):
        keyword = m.group(1).lower()
        value = m.group(2)
        if value.lower() in _PLACEHOLDER_VALUES:
            continue
        if re.fullmatch(r"[\d.]+", value):            # version/number
            continue
        if value.startswith(("http", "/", "./", "#", "{{", "$")):  # url/template
            continue
        ent = _shannon_entropy(value)
        is_user_field = keyword in ("username", "user_name", "user-name", "login")
        if is_user_field:
            add("Username/Login", "low", m.group(0), value, m.start(), m.end())
            continue
        # password/token/secret: keep if long-ish or high entropy
        if len(value) >= 8 or ent >= 3.0:
            sev = "high" if ("secret" in keyword or "password" in keyword
                             or "pwd" in keyword or "token" in keyword
                             or "key" in keyword) else "medium"
            add(f"Generic secret ({keyword})", sev, m.group(0), value,
                m.start(), m.end())

    # standalone username hints (info only, dedup with above)
    for m in _USERNAME_HINT.finditer(text):
        value = m.group(1)
        if value.lower() in _PLACEHOLDER_VALUES:
            continue
        add("Username/Email hint", "low", m.group(0), value, m.start(), m.end())

    return findings
