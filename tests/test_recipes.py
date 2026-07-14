# test_recipes.py
from wp import recipes as wp_recipes

def test_file_manager_recipe_present():
    recs = wp_recipes.find_recipes("wp-file-manager")
    assert len(recs) >= 1
    r = recs[0]
    assert r["cve"] == "CVE-2020-25213"
    assert r["affected"] == "<=6.8"
    assert r["endpoint"] == "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
    assert r["field"] == "upload[]"
    assert "{filename}" in r["upload_path"]
    assert r["source"] == "registry"

def test_find_unknown_returns_empty():
    assert wp_recipes.find_recipes("does-not-exist") == []

def test_all_recipes_have_required_keys():
    required = {"plugin","cve","affected","method","endpoint","params","field","upload_path","source","note"}
    for r in wp_recipes.RECIPES:
        assert required <= set(r.keys()), f"missing keys in {r.get('plugin')}"


def test_kirki_oob_takeover_recipe_present():
    recs = wp_recipes.find_privesc("kirki")
    assert len(recs) == 1
    r = recs[0]
    assert r["cve"] == "CVE-2026-8206"
    assert r["kind"] == "account-takeover-oob"
    assert r["affected"] == ">=6.0.0,<=6.0.6"
    assert r["endpoint"] == "/wp-json/KirkiComponentLibrary/v1/kirki-forgot-password"
    assert r["user_param"] == "username" and r["email_param"] == "email"
    assert r["success_marker"] == "Email sent"
    assert r["source"] == "registry"


def test_opal_estate_privesc_recipe_present():
    recs = wp_recipes.find_privesc("opal-estate-pro")
    assert len(recs) == 1
    r = recs[0]
    assert r["cve"] == "CVE-2025-6934"
    assert r["kind"] == "register-role"
    assert r["affected"] == "<=1.7.5"
    assert r["endpoint"] == "/wp-admin/admin-ajax.php"
    assert r["action"] == "opalestate_register_form"
    assert r["role_param"] == "role" and r["role_value"] == "administrator"
    assert r["pass_confirm_field"] == "password1"
    assert r["nonce_from"]["field"] == "opalestate-register-nonce"
    assert r["source"] == "registry"
