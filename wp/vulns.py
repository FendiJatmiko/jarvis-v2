"""Track A — check installed plugin versions against current vulnerability intel.

Webshell-focused: every finding is classified by whether it can lead to a
webshell — either DIRECTLY (file upload / RCE / code or command injection /
RFI / deserialization) or as a PRECURSOR (unauth privilege-escalation /
auth-bypass / account-takeover → admin → editor/plugin-upload → webshell,
which Track B chains). Non-webshell classes (XSS, CSRF, SQLi) are reported
but flagged out-of-scope so they don't distract from the objective.

Primary source: a Wordfence-Intelligence-style feed (loaded via load_feed).
Fallback: RAGFlow / LLM, injected as functions (no hard dependency).
"""
import json
import os
import re
import time

WORDFENCE_V3_PRODUCTION = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"

# CWE ids whose exploitation yields code execution on the server → webshell-class.
WEBSHELL_CWES = {"434", "94", "95", "96", "98", "78", "77", "502"}

# CWE ids that, on their own, mean an attacker gains admin/account control —
# privilege management (269/266), broken authentication (287), password
# reset/change (640/620). Not code-exec themselves, but the DOOR to a webshell:
# unauth → admin → theme/plugin editor or plugin-upload → shell. These are
# reliable "webshell precursors" — Track B (phase_track_b) chains them.
PRECURSOR_CWES = {"269", "266", "287", "640", "620"}

# Broader authorization-gap CWEs. Missing/incorrect authorization (862/863) and
# improper access control (284) cover privilege escalation AND pure
# information-disclosure / IDOR (e.g. CVE-2026-1004 — an unauth WooCommerce
# product-data leak, CVSS 5.3, no path to admin). The CWE alone can't tell those
# apart, so — unlike PRECURSOR_CWES above — a weak-authz CWE counts as a webshell
# precursor ONLY with a corroborating privesc signal in the title (_PRECURSOR_KW),
# and never when the title self-identifies as an info leak (_INFO_DISCLOSURE_KW).
WEAK_AUTHZ_CWES = {"862", "863", "284"}

# Title keywords used when a record carries no/'unknown' CWE.
_WEBSHELL_KW = [
    ("file-upload", ["arbitrary file upload", "unrestricted file upload", "unrestricted upload", "file upload"]),
    ("rce", ["remote code execution", "code execution", "code injection"]),
    ("command-injection", ["command injection", "os command"]),
    ("rfi", ["remote file inclusion", "local file inclusion", "file inclusion"]),
    ("deserialization", ["deserialization", "php object injection", "object injection"]),
]

# Conservative keyword fallback for the precursor class (when CWE is missing).
_PRECURSOR_KW = [
    ("privesc", ["privilege escalation", "administrative user creation",
                 "arbitrary user creation", "admin account creation"]),
    ("auth-bypass", ["authentication bypass", "auth bypass"]),
    ("acct-takeover", ["account takeover", "arbitrary password reset"]),
]

# Title phrases that mark a finding as pure information disclosure. Under a
# weak-authz CWE (862/863/284) this disqualifies it from the precursor tier —
# it's a confidentiality leak, not a step toward admin/RCE.
_INFO_DISCLOSURE_KW = ("information disclosure", "sensitive information",
                       "information exposure", "info disclosure",
                       "data exposure", "data disclosure")

# On an open-registration WordPress, these roles are effectively "anyone" — a
# privesc that needs only one of them is a real door. Higher roles already imply
# meaningful access, so a privesc gated behind them isn't an entry point.
_LOW_PRIV_ROLES = ("subscriber", "contributor", "customer")


def _precursor_reachable(title):
    """Is this precursor an actual entry point? True if unauthenticated, or
    authenticated but needing only a low-privilege role (subscriber/contributor
    /customer). Authenticated privesc requiring author/editor/admin is skipped."""
    if "unauthenticated" in title:
        return True
    if "authenticated" in title:
        return any(r in title for r in _LOW_PRIV_ROLES)
    return False


def _cwe_ids(cwe):
    """Normalise the many shapes a 'cwe' field takes into a set of bare ids."""
    ids = set()
    items = cwe if isinstance(cwe, list) else [cwe]
    for it in items:
        if isinstance(it, dict):
            it = it.get("id") or it.get("name") or ""
        for m in re.findall(r"(?:CWE-)?(\d+)", str(it)):
            ids.add(m)
    return ids


def classify(cwe, title):
    """Return (relevant: bool, klass: str) for a vuln record.

    In-scope classes: direct server code-exec (webshell) AND privilege-
    escalation / auth-bypass / account-takeover precursors that are a real
    entry point (unauth, or low-priv authenticated). Everything else
    (XSS/CSRF/IDOR/SQLi/info-disclosure) is out of scope."""
    ids = _cwe_ids(cwe)
    t = (title or "").lower()

    # 1. Direct code execution — by CWE.
    if ids & WEBSHELL_CWES:
        if "434" in ids:
            return True, "file-upload"
        if ids & {"78", "77"}:
            return True, "command-injection"
        if ids & {"98"}:
            return True, "rfi"
        if "502" in ids:
            return True, "deserialization"
        return True, "rce"
    # 2. Direct code execution — by title (when CWE is missing/unknown).
    for klass, kws in _WEBSHELL_KW:
        if any(k in t for k in kws):
            return True, klass
    # 3. Precursor (grants admin → webshell). In scope when it's a real entry
    #    point: unauthenticated, or authenticated needing only a low-priv role.
    if _precursor_reachable(t):
        # Strong precursor CWEs imply account/role compromise on their own.
        if ids & {"287"}:
            return True, "auth-bypass"
        if ids & {"640"}:
            return True, "acct-takeover"
        if ids & PRECURSOR_CWES:
            return True, "privesc"
        # Weak-authz CWEs (862/863/284) are ambiguous, and a genuine privesc may
        # also carry a CWE we don't list — so fall back to a title signal. But a
        # title that self-identifies as info-disclosure is a confidentiality leak,
        # not a webshell precursor: leave it out of scope (e.g. CVE-2026-1004).
        if not any(k in t for k in _INFO_DISCLOSURE_KW):
            for klass, kws in _PRECURSOR_KW:
                if any(k in t for k in kws):
                    return True, klass
    return False, "other"


def precondition(cwe, title):
    """For an IN-SCOPE (code-exec-class) finding, how self-contained is it?
    The webshell CWEs alone over-state 'auto-exploitable' — an authenticated or
    deserialization bug isn't a clean unauth shell. Returns:
      self-contained  — unauth direct code exec (the genuinely automatable ones)
      needs-lowpriv   — authenticated, but only subscriber/contributor/customer
      needs-auth      — authenticated at author/editor/admin (a foothold, not entry)
      needs-gadget    — object injection / deserialization: needs a POP chain elsewhere
      needs-lfi-chain — file inclusion: needs url_include or an includable file
    This is heuristic (title/CWE), NOT a guarantee a self-contained one is truly
    weaponizable — per-CVE reality still decides (e.g. paper RCEs)."""
    ids = _cwe_ids(cwe)
    t = (title or "").lower()
    if "502" in ids or "object injection" in t or "deserial" in t:
        return "needs-gadget"
    if "authenticated" in t and "unauthenticated" not in t:
        if any(r in t for r in _LOW_PRIV_ROLES):
            return "needs-lowpriv"
        return "needs-auth"
    if "file inclusion" in t or "98" in ids:
        return "needs-lfi-chain"
    return "self-contained"


# Classes that don't give a shell/admin on their own, but are a plausible link
# in a chain — with a victim (CSRF/XSS), an existing foothold (authed-only
# privesc), or a further step (SQLi→creds, SSRF→internal). Surfaced, not
# auto-exploited: the tool can't produce a confirmed shell from these.
CHAIN_CWES = {
    "352": "csrf-chain",
    "79": "xss-chain", "80": "xss-chain",
    "918": "ssrf",
    "89": "sqli",
    "639": "access-control", "566": "access-control", "1216": "access-control",
}
_CHAIN_KW = [
    ("csrf-chain", ["cross-site request forgery"]),
    ("xss-chain", ["cross-site scripting"]),
    ("sqli", ["sql injection"]),
    ("ssrf", ["server-side request forgery"]),
    ("privesc-chain", ["privilege escalation"]),   # authed/high-priv → needs a foothold
    ("auth-chain", ["authentication bypass"]),
]


def chain_class(cwe, title):
    """For a finding that isn't auto-exploitable: is it a plausible chain to
    admin/RCE (needs a victim, phishing, or an existing foothold)? Returns a
    chain-class label, or None if genuinely out of scope."""
    ids = _cwe_ids(cwe)
    for cid, klass in CHAIN_CWES.items():
        if cid in ids:
            return klass
    t = (title or "").lower()
    for klass, kws in _CHAIN_KW:
        if any(k in t for k in kws):
            return klass
    return None


def _tier(cwe, title):
    """Three-way triage → (tier, klass). tier: 'inscope' (auto-exploitable
    webshell/privesc), 'chain' (needs victim/foothold), or 'out'."""
    relevant, klass = classify(cwe, title)
    if relevant:
        return "inscope", klass
    ck = chain_class(cwe, title)
    if ck:
        return "chain", ck
    return "out", "other"


def _vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))) or (0,)


def _cmp(a, b):
    la, lb = list(a), list(b)
    while len(la) < len(lb):
        la.append(0)
    while len(lb) < len(la):
        lb.append(0)
    return (la > lb) - (la < lb)


def _in_range(version, rng):
    """rng: {from_version, from_inclusive, to_version, to_inclusive} ('*' = open)."""
    v = _vtuple(version)
    fv = rng.get("from_version", "*")
    tv = rng.get("to_version", "*")
    if fv not in ("*", "", None):
        c = _cmp(v, _vtuple(fv))
        if c < 0 or (c == 0 and not rng.get("from_inclusive", True)):
            return False
    if tv not in ("*", "", None):
        c = _cmp(v, _vtuple(tv))
        if c > 0 or (c == 0 and not rng.get("to_inclusive", True)):
            return False
    return True


def _affects(version, record):
    for sw in record.get("software", []):
        if sw.get("type") == "plugin":
            for rng in (sw.get("affected_versions") or {}).values():
                if _in_range(version, rng):
                    return True
    return False


def _patched_version(record):
    for sw in record.get("software", []):
        pv = sw.get("patched_versions") or []
        if pv:
            return pv[0]
    return None


def _finding(record, slug, version, source):
    tier, klass = _tier(record.get("cwe"), record.get("title"))
    f = {
        "slug": slug,
        "version": version,
        "cve": record.get("cve"),
        "title": record.get("title", ""),
        "klass": klass,
        "relevant": tier == "inscope",   # auto-exploitable (webshell/privesc)
        "tier": tier,                    # inscope | chain | out
        "patched": _patched_version(record),
        "source": source,
    }
    if tier == "inscope":
        f["precondition"] = precondition(record.get("cwe"), record.get("title"))
    return f


def load_feed(path):
    """Load a Wordfence-style feed JSON file → {slug: [records]} index.

    Accepts either a dict keyed by vuln-id or a list of records. Never raises;
    returns {} on any problem so the caller falls back to RAGFlow/LLM.
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return {}
    records = data.values() if isinstance(data, dict) else data
    index = {}
    for rec in records:
        for sw in rec.get("software", []):
            if sw.get("type") == "plugin" and sw.get("slug"):
                index.setdefault(sw["slug"], []).append(rec)
    return index


def refresh_feed(api_key, cache_path, url=WORDFENCE_V3_PRODUCTION):
    """Fetch the Wordfence V3 feed with a Bearer key → write cache_path.
    Returns True on success. Never raises (Track A degrades to RAGFlow)."""
    if not api_key:
        return False
    try:
        import requests
        r = requests.get(url, headers={"Authorization": f"Bearer {api_key}"}, timeout=120)
        r.raise_for_status()
        with open(cache_path, "w") as f:
            f.write(r.text)
        return True
    except Exception:
        return False


def feed_index(cache_path, api_key=None, max_age_days=7):
    """Return the {slug: [records]} vuln index.

    Uses a fresh cache if present; if stale (or missing) and an api_key is
    available, refreshes first; if refresh isn't possible, falls back to a
    stale cache when one exists, else {} (→ caller uses RAGFlow only).
    """
    fresh = False
    if os.path.exists(cache_path):
        age = time.time() - os.path.getmtime(cache_path)
        fresh = age < max_age_days * 86400
    if not fresh and api_key:
        refresh_feed(api_key, cache_path)
    if os.path.exists(cache_path):
        return load_feed(cache_path)
    return {}


def lookup(slug, version, feed_index=None, ragflow_fn=None, llm_fn=None):
    """Findings for one installed plugin. Feed first, RAGFlow/LLM fallback."""
    findings = []
    if feed_index and slug in feed_index:
        for rec in feed_index[slug]:
            if _affects(version, rec):
                findings.append(_finding(rec, slug, version, "wordfence"))
    if not findings and ragflow_fn:
        syn = _ragflow_lookup(slug, version, ragflow_fn, llm_fn)
        if syn:
            findings.append(syn)
    return findings


def _ragflow_lookup(slug, version, ragflow_fn, llm_fn):
    ctx = ragflow_fn(
        f"known vulnerability in WordPress plugin {slug} version {version}: "
        f"CVE, CWE, and whether it allows arbitrary file upload or remote code execution"
    )
    if not ctx:
        return None
    tier, klass = _tier("", ctx)
    f = {
        "slug": slug,
        "version": version,
        "cve": None,
        "title": ctx.strip()[:160],
        "klass": klass,
        "relevant": tier == "inscope",
        "tier": tier,
        "patched": None,
        "source": "ragflow",
    }
    if tier == "inscope":
        f["precondition"] = precondition("", ctx)
    return f
