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
    assert f["webshell_relevant"] is True
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
    assert out[0]["webshell_relevant"] is False

def test_lookup_ragflow_fallback_when_not_in_feed():
    ragflow = MagicMock(return_value="CVE-2099-1 arbitrary file upload in obscure-plugin")
    out = wp_vulns.lookup("obscure-plugin", "1.0", feed_index={}, ragflow_fn=ragflow, llm_fn=None)
    assert len(out) == 1
    assert out[0]["source"] == "ragflow"
    assert out[0]["webshell_relevant"] is True

def test_lookup_no_fallback_without_ragflow():
    assert wp_vulns.lookup("obscure-plugin", "1.0", feed_index={}) == []
