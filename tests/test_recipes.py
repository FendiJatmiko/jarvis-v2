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

def test_wpdiscuz_recipe_harvests_nonce_instead_of_hardcoding_empty():
    recs = wp_recipes.find_recipes("wpdiscuz")
    assert len(recs) == 1
    r = recs[0]
    assert r["cve"] == "CVE-2020-24186"
    assert r["affected"] == ">=7.0.0,<=7.0.4"
    assert r["params"]["action"] == "wmuUploadFiles"
    assert "wmu_nonce" not in r["params"]  # no more hardcoded empty nonce
    assert r["nonce_from"] == {"url": "/", "key": "wmuSecurity", "param": "wmu_nonce"}
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


def test_ninja_forms_uploads_recipe_present():
    recs = wp_recipes.find_recipes("ninja-forms-uploads")
    assert len(recs) == 1
    r = recs[0]
    assert r["cve"] == "CVE-2026-0740"
    assert r["affected"] == "<=3.3.24"
    assert r["mode"] == "nonce-traversal"
    assert r["nonce_action"] == "nf_fu_get_new_nonce"
    assert r["upload_action"] == "nf_fu_upload"
    assert r["dest_param"] == "image_jpg"
    assert r["source"] == "registry"


def test_simple_file_list_recipe_present():
    recs = wp_recipes.find_recipes("simple-file-list")
    assert len(recs) == 1
    r = recs[0]
    assert r["cve"] == "CVE-2025-34085"
    assert r["affected"] == "<=4.2.2"
    assert r["mode"] == "upload-then-rename"
    assert r["rename_endpoint"] == "/wp-content/plugins/simple-file-list/ee-file-engine.php"
    assert r["token_salt"] == "unique_salt"
    assert r["upload_dir"] == "/wp-content/uploads/simple-file-list/"
    assert r["source"] == "registry"


def test_breeze_recipe_present():
    recs = wp_recipes.find_recipes("breeze")
    assert len(recs) == 1
    r = recs[0]
    assert r["cve"] == "CVE-2026-3844"
    assert r["affected"] == "<=2.4.4"
    assert r["mode"] == "comment-avatar-ssrf"
    assert r["endpoint"] == "/wp-comments-post.php"
    assert r["author_field"] == "author"
    assert r["upload_path"] == "/wp-content/cache/breeze-extra/gravatars/{filename}"
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
