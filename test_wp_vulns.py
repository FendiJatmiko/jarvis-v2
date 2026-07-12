from unittest.mock import MagicMock
import json
import wp_vulns


# ── classify: webshell-relevance by CWE + title ──────────────────────────────
def test_classify_file_upload_cwe434():
    wr, klass = wp_vulns.classify(["CWE-434"], "Arbitrary File Upload")
    assert wr is True and klass == "file-upload"

def test_classify_rce_cwe94():
    wr, klass = wp_vulns.classify(["CWE-94"], "Remote Code Execution")
    assert wr is True and klass == "rce"

def test_classify_command_injection():
    wr, klass = wp_vulns.classify([{"id": "CWE-78"}], "OS Command Injection")
    assert wr is True and klass == "command-injection"

def test_classify_xss_is_out_of_scope():
    wr, klass = wp_vulns.classify(["CWE-79"], "Stored Cross-Site Scripting")
    assert wr is False and klass == "other"

def test_classify_csrf_is_out_of_scope():
    wr, klass = wp_vulns.classify(["CWE-352"], "CSRF")
    assert wr is False

def test_classify_falls_back_to_title_when_no_cwe():
    wr, klass = wp_vulns.classify([], "Unauthenticated Arbitrary File Upload")
    assert wr is True and klass == "file-upload"


# ── precursor class (privesc / auth-bypass → admin → webshell) ────────────────
def test_classify_unauth_privesc_is_precursor():
    wr, klass = wp_vulns.classify({"id": 269, "name": "Improper Privilege Management"},
        "LA-Studio Element Kit <= 1.5.6.3 - Unauthenticated Privilege Escalation via Backdoor")
    assert wr is True and klass == "privesc"     # CVE-2026-0920 now FLAGGED, not skipped

def test_classify_missing_authz_unauth_is_precursor():
    wr, klass = wp_vulns.classify(["CWE-862"], "Foo <= 1.0 - Unauthenticated Privilege Escalation")
    assert wr is True and klass == "privesc"

def test_classify_unauth_auth_bypass():
    wr, klass = wp_vulns.classify(["CWE-287"], "Bar <= 2.0 - Unauthenticated Authentication Bypass")
    assert wr is True and klass == "auth-bypass"

def test_classify_low_priv_authed_privesc_is_precursor():
    # subscriber/contributor are effectively "anyone" on open-registration WP → in scope
    wr, klass = wp_vulns.classify(["CWE-269"], "Baz <= 1.0 - Authenticated (Subscriber+) Privilege Escalation")
    assert wr is True and klass == "privesc"

def test_classify_contributor_privesc_is_precursor():
    wr, klass = wp_vulns.classify(["CWE-269"], "Qux <= 2.0 - Authenticated (Contributor+) Privilege Escalation")
    assert wr is True and klass == "privesc"

def test_classify_high_priv_authed_privesc_skipped():
    # needs Editor already → not an entry point → out of scope
    wr, klass = wp_vulns.classify(["CWE-269"], "Zap <= 1.0 - Authenticated (Editor+) Privilege Escalation")
    assert wr is False and klass == "other"

def test_classify_authed_low_priv_xss_still_skipped():
    # low-priv role but XSS (not privesc/webshell CWE) → not auto-exploitable
    wr, klass = wp_vulns.classify(["CWE-79"], "Shortcodes <= 7.0 - Authenticated (Contributor+) Stored XSS")
    assert wr is False and klass == "other"


# ── precondition: how self-contained is an in-scope finding really ────────────
def test_precondition_unauth_file_upload_is_self_contained():
    assert wp_vulns.precondition(["CWE-434"], "Unauthenticated Arbitrary File Upload") == "self-contained"

def test_precondition_admin_file_upload_needs_auth():
    assert wp_vulns.precondition(["CWE-434"],
        "RevSlider <= 6.6.12 - Authenticated (Administrator+) Arbitrary File Upload") == "needs-auth"

def test_precondition_subscriber_upload_needs_lowpriv():
    assert wp_vulns.precondition(["CWE-434"],
        "Foo <= 1.0 - Authenticated (Subscriber+) Arbitrary File Upload") == "needs-lowpriv"

def test_precondition_deserialization_needs_gadget():
    assert wp_vulns.precondition(["CWE-502"],
        "Master Slider Pro <= 3.6.5 - Unauthenticated PHP Object Injection") == "needs-gadget"

def test_precondition_object_injection_by_title_needs_gadget():
    assert wp_vulns.precondition([], "Unauthenticated PHP Object Injection") == "needs-gadget"

def test_precondition_file_inclusion_needs_chain():
    assert wp_vulns.precondition(["CWE-98"], "Unauthenticated Remote File Inclusion") == "needs-lfi-chain"

def test_finding_carries_precondition_for_inscope():
    f = wp_vulns._finding(
        {"cve": "CVE-x", "cwe": ["CWE-434"], "title": "Unauthenticated Arbitrary File Upload",
         "software": []}, "p", "1.0", "wordfence")
    assert f["precondition"] == "self-contained"

def test_finding_no_precondition_key_when_out_of_scope():
    f = wp_vulns._finding(
        {"cve": "CVE-y", "cwe": ["CWE-200"], "title": "Information Disclosure", "software": []},
        "p", "1.0", "wordfence")
    assert "precondition" not in f     # only in-scope findings get graded


# ── chain candidates (plausible path to admin/RCE, not auto-exploitable) ──────
def test_chain_class_csrf():
    assert wp_vulns.chain_class(["CWE-352"], "Plugin <= 1.0 - CSRF") == "csrf-chain"

def test_chain_class_xss():
    assert wp_vulns.chain_class(["CWE-79"], "Plugin <= 1.0 - Stored XSS") == "xss-chain"

def test_chain_class_sqli():
    assert wp_vulns.chain_class(["CWE-89"], "Plugin <= 1.0 - SQL Injection") == "sqli"

def test_chain_class_idor_access_control():
    assert wp_vulns.chain_class(["CWE-639"], "Plugin <= 1.0 - Insecure Direct Object Reference") == "access-control"

def test_chain_class_none_for_info_disclosure():
    assert wp_vulns.chain_class(["CWE-200"], "Plugin <= 1.0 - Information Disclosure") is None

def test_tier_three_way():
    # webshell → inscope ; XSS → chain ; info-disclosure → out
    assert wp_vulns._tier(["CWE-434"], "Arbitrary File Upload")[0] == "inscope"
    assert wp_vulns._tier(["CWE-79"], "Stored XSS")[0] == "chain"
    assert wp_vulns._tier(["CWE-200"], "Information Disclosure")[0] == "out"

def test_lookup_xss_is_chain_tier(tmp_path):
    idx = wp_vulns.load_feed(_write_feed(tmp_path))
    out = wp_vulns.lookup("xss-plugin", "2.0", feed_index=idx)
    assert out[0]["tier"] == "chain"
    assert out[0]["relevant"] is False        # surfaced, but not auto-exploitable
    assert out[0]["klass"] == "xss-chain"


# ── version range matching ───────────────────────────────────────────────────
def test_in_range_inclusive_upper():
    rng = {"from_version": "*", "to_version": "6.8", "to_inclusive": True}
    assert wp_vulns._in_range("6.0", rng) is True
    assert wp_vulns._in_range("6.8", rng) is True
    assert wp_vulns._in_range("6.9", rng) is False

def test_in_range_exclusive_upper():
    rng = {"from_version": "1.0", "from_inclusive": True, "to_version": "2.0", "to_inclusive": False}
    assert wp_vulns._in_range("2.0", rng) is False
    assert wp_vulns._in_range("1.9", rng) is True
    assert wp_vulns._in_range("0.9", rng) is False


# ── feed loading + lookup ─────────────────────────────────────────────────────
WF_RECORD = {
    "title": "Vuln Plugin <= 1.2 - Unauthenticated Arbitrary File Upload",
    "cve": "CVE-2024-0001",
    "cwe": ["CWE-434"],
    "software": [{
        "type": "plugin", "slug": "vuln-plugin",
        "affected_versions": {"* - 1.2": {"from_version": "*", "to_version": "1.2", "to_inclusive": True}},
        "patched_versions": ["1.3"],
    }],
}
XSS_RECORD = {
    "title": "Safe-ish Plugin <= 3.0 - Stored XSS",
    "cve": "CVE-2024-0002",
    "cwe": ["CWE-79"],
    "software": [{
        "type": "plugin", "slug": "xss-plugin",
        "affected_versions": {"* - 3.0": {"from_version": "*", "to_version": "3.0", "to_inclusive": True}},
    }],
}

def _write_feed(tmp_path):
    p = tmp_path / "feed.json"
    p.write_text(json.dumps({"id-1": WF_RECORD, "id-2": XSS_RECORD}))
    return str(p)

def test_load_feed_indexes_by_slug(tmp_path):
    idx = wp_vulns.load_feed(_write_feed(tmp_path))
    assert "vuln-plugin" in idx and "xss-plugin" in idx

def test_load_feed_missing_file_returns_empty():
    assert wp_vulns.load_feed("/no/such/file.json") == {}

def test_lookup_flags_webshell_vuln_in_range(tmp_path):
    idx = wp_vulns.load_feed(_write_feed(tmp_path))
    out = wp_vulns.lookup("vuln-plugin", "1.1", feed_index=idx)
    assert len(out) == 1
    f = out[0]
    assert f["cve"] == "CVE-2024-0001"
    assert f["relevant"] is True
    assert f["klass"] == "file-upload"
    assert f["patched"] == "1.3"
    assert f["source"] == "wordfence"

def test_lookup_patched_version_not_flagged(tmp_path):
    idx = wp_vulns.load_feed(_write_feed(tmp_path))
    assert wp_vulns.lookup("vuln-plugin", "1.3", feed_index=idx) == []

def test_lookup_xss_reported_but_not_webshell(tmp_path):
    idx = wp_vulns.load_feed(_write_feed(tmp_path))
    out = wp_vulns.lookup("xss-plugin", "2.0", feed_index=idx)
    assert len(out) == 1
    assert out[0]["relevant"] is False

def test_lookup_ragflow_fallback_when_not_in_feed():
    ragflow = MagicMock(return_value="CVE-2099-1 arbitrary file upload in obscure-plugin")
    out = wp_vulns.lookup("obscure-plugin", "1.0", feed_index={}, ragflow_fn=ragflow, llm_fn=None)
    assert len(out) == 1
    assert out[0]["source"] == "ragflow"
    assert out[0]["relevant"] is True

def test_lookup_no_fallback_without_ragflow():
    assert wp_vulns.lookup("obscure-plugin", "1.0", feed_index={}) == []


# ── Wordfence fetch + staleness cache ────────────────────────────────────────
def test_refresh_feed_no_key_returns_false(tmp_path):
    assert wp_vulns.refresh_feed(None, str(tmp_path / "f.json")) is False

def test_refresh_feed_writes_cache(tmp_path, monkeypatch):
    cache = tmp_path / "f.json"
    resp = MagicMock(); resp.text = json.dumps({"id-1": WF_RECORD}); resp.raise_for_status = lambda: None
    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: resp)
    ok = wp_vulns.refresh_feed("wfi_key", str(cache))
    assert ok is True
    assert "vuln-plugin" in wp_vulns.load_feed(str(cache))

def test_feed_index_uses_fresh_cache_without_fetch(tmp_path, monkeypatch):
    cache = _write_feed(tmp_path)   # just-written → fresh
    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not fetch")))
    idx = wp_vulns.feed_index(cache, api_key="wfi_key")
    assert "vuln-plugin" in idx

def test_feed_index_missing_no_key_returns_empty(tmp_path):
    assert wp_vulns.feed_index(str(tmp_path / "nope.json"), api_key=None) == {}

def test_feed_index_refreshes_when_missing_and_key(tmp_path, monkeypatch):
    cache = tmp_path / "f.json"
    resp = MagicMock(); resp.text = json.dumps({"id-1": WF_RECORD}); resp.raise_for_status = lambda: None
    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: resp)
    idx = wp_vulns.feed_index(str(cache), api_key="wfi_key")
    assert "vuln-plugin" in idx
