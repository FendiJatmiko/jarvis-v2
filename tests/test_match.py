# test_match.py
from wp import match as wp_match
from unittest.mock import MagicMock
import json

def test_le_constraint():
    assert wp_match.version_satisfies("6.0", "<=6.8") is True
    assert wp_match.version_satisfies("6.8", "<=6.8") is True
    assert wp_match.version_satisfies("6.9", "<=6.8") is False

def test_range_constraint():
    assert wp_match.version_satisfies("7.0.4", ">=7.0.0,<=7.0.4") is True
    assert wp_match.version_satisfies("7.0.5", ">=7.0.0,<=7.0.4") is False
    assert wp_match.version_satisfies("6.9.9", ">=7.0.0,<=7.0.4") is False

def test_uneven_length_versions():
    assert wp_match.version_satisfies("6", "<=6.8") is True
    assert wp_match.version_satisfies("6.8.1", "<=6.8") is False

def test_exact_default_operator():
    assert wp_match.version_satisfies("6.8", "6.8") is True
    assert wp_match.version_satisfies("6.7", "6.8") is False

def test_match_registry_hit():
    info = {"plugins": [{"slug": "wp-file-manager", "version": "6.0"}]}
    out = wp_match.match(info)
    assert len(out) == 1
    assert out[0]["cve"] == "CVE-2020-25213"
    assert out[0]["source"] == "registry"

def test_match_version_out_of_range_no_hit():
    info = {"plugins": [{"slug": "wp-file-manager", "version": "6.9"}]}
    assert wp_match.match(info) == []

def test_match_llm_fallback_ranks_after_registry():
    info = {"plugins": [
        {"slug": "wp-file-manager", "version": "6.0"},
        {"slug": "obscure-plugin", "version": "1.2"},
    ]}
    ragflow = MagicMock(return_value="CVE-2099-0001 arbitrary upload in obscure-plugin")
    synth = {"plugin": "obscure-plugin", "cve": "CVE-2099-0001", "affected": "<=1.2",
             "method": "POST", "endpoint": "/x", "params": {}, "field": "file",
             "upload_path": "/wp-content/uploads/{filename}", "note": "synth"}
    llm = MagicMock(return_value=json.dumps(synth))
    out = wp_match.match(info, ragflow_fn=ragflow, llm_fn=llm)
    assert [c["source"] for c in out] == ["registry", "llm"]
    assert out[1]["cve"] == "CVE-2099-0001"

def test_match_no_fallback_when_ragflow_none():
    info = {"plugins": [{"slug": "obscure-plugin", "version": "1.2"}]}
    assert wp_match.match(info) == []
