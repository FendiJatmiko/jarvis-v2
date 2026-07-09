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

# CWE ids that grant an attacker admin access (privilege escalation / broken
# auth / missing authorization). Not code-exec themselves, but the DOOR to a
# webshell: unauth → admin → theme/plugin editor or plugin-upload → shell.
# These are "webshell precursors" — Track B (phase_track_b) chains them.
PRECURSOR_CWES = {"269", "862", "863", "284", "266", "287", "640", "620"}

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
    """Return (webshell_relevant: bool, klass: str) for a vuln record."""
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
    # 3. Precursor (grants admin → webshell) — ONLY when unauthenticated.
    #    An authenticated privesc needs an account already, so it's not a door.
    if "unauthenticated" in t:
        if ids & {"287"}:
            return True, "auth-bypass"
        if ids & {"640"}:
            return True, "acct-takeover"
        if ids & PRECURSOR_CWES:
            return True, "privesc"
        for klass, kws in _PRECURSOR_KW:
            if any(k in t for k in kws):
                return True, klass
    return False, "other"


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
    wr, klass = classify(record.get("cwe"), record.get("title"))
    return {
        "slug": slug,
        "version": version,
        "cve": record.get("cve"),
        "title": record.get("title", ""),
        "klass": klass,
        "webshell_relevant": wr,
        "patched": _patched_version(record),
        "source": source,
    }


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
    wr, klass = classify("", ctx)
    return {
        "slug": slug,
        "version": version,
        "cve": None,
        "title": ctx.strip()[:160],
        "klass": klass,
        "webshell_relevant": wr,
        "patched": None,
        "source": "ragflow",
    }
