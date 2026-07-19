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

# Modes that read the REAL stored path back out of the server's response instead
# of templating a guess (wpdiscuz stores at an unguessable
# /uploads/YYYY/MM/<name>-<microtime>.php and returns the url in its JSON).
RESPONSE_PATH_MODES = {"comment-image-upload"}

def test_all_recipes_have_required_keys():
    required = {"plugin","cve","affected","method","endpoint","params","field","source","note"}
    for r in wp_recipes.RECIPES:
        assert required <= set(r.keys()), f"missing keys in {r.get('plugin')}"
        # upload_path is required only for recipes that template their landing
        # path; response-path modes derive it from the reply and omit it.
        if r.get("mode") not in RESPONSE_PATH_MODES:
            assert "upload_path" in r, f"missing upload_path in {r.get('plugin')}"


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


def test_essential_addons_privesc_recipe_present():
    recs = wp_recipes.find_privesc("essential-addons-for-elementor-lite")
    assert len(recs) == 1
    r = recs[0]
    assert r["cve"] == "CVE-2023-32243"
    assert r["kind"] == "password-reset"
    assert r["affected"] == ">=5.4.0,<=5.7.1"
    assert r["endpoint"] == "/wp-admin/admin-ajax.php"
    assert r["target_user"] == "admin"
    assert r["user_param"] == "rp_login"
    assert r["pass_param"] == "eael-pass1"
    assert r["pass_confirm_param"] == "eael-pass2"
    assert r["params"]["action"] == "login_or_register_user"
    assert r["params"]["eael-resetpassword-submit"] == "1"
    assert r["nonce_from"] == {"url": "/", "key": "nonce", "param": "eael-resetpassword-nonce"}
    assert r["source"] == "registry"


def test_king_addons_upload_recipe_present():
    recs = wp_recipes.find_recipes("king-addons")
    assert len(recs) == 1
    r = recs[0]
    assert r["cve"] == "CVE-2025-6327"
    assert r["affected"] == "<=51.1.14"
    assert r["endpoint"] == "/wp-admin/admin-ajax.php"
    assert r["params"]["action"] == "king_addons_upload_file"
    assert r["params"]["triggering_event"] == "click"
    assert r["field"] == "uploaded_file"
    assert r["upload_path"] == "/wp-content/uploads/king-addons/forms/{filename}"
    assert r["nonce_from"] == {"url": "/", "key": "nonce", "object": "KingAddonsFormBuilderData",
                               "param": "king_addons_fb_nonce"}
    assert r["source"] == "registry"


def test_king_addons_privesc_recipe_present():
    recs = wp_recipes.find_privesc("king-addons")
    assert len(recs) == 1
    r = recs[0]
    assert r["cve"] == "CVE-2025-6325"
    assert r["kind"] == "register-role"
    assert r["affected"] == "<=51.1.14"
    assert r["endpoint"] == "/wp-admin/admin-ajax.php"
    assert r["action"] == "king_addons_user_register"
    assert r["user_field"] == "username" and r["email_field"] == "email"
    assert r["pass_field"] == "password" and r["pass_confirm_field"] == "confirm_password"
    assert r["role_param"] == "user_role" and r["role_value"] == "administrator"
    assert r["nonce_from"] == {"url": "/", "key": "register_nonce",
                               "object": "king_addons_login_register_vars", "param": "nonce"}
    assert r["source"] == "registry"


def test_wp_automatic_sqli_recipe_present():
    recs = wp_recipes.find_sqli("wp-automatic")
    assert len(recs) == 1
    r = recs[0]
    assert r["cve"] == "CVE-2024-27956"
    assert r["affected"] == "<=3.92.0"
    assert r["kind"] == "time-blind"
    assert r["method"] == "GET"
    assert r["endpoint"] == "/wp-content/plugins/wp-automatic/inc/csv.php"
    assert r["inject_param"] == "q"
    assert r["params"]["auth"] == "\x00"          # NULL byte, not literal "%00"
    assert r["integrity"] == {"param": "integ", "algo": "md5"}
    assert r["source"] == "registry"


def test_lastudio_privesc_recipe_present():
    recs = wp_recipes.find_privesc("lastudio-element-kit")
    assert len(recs) == 1
    r = recs[0]
    assert r["cve"] == "CVE-2026-0920"
    assert r["affected"] == "<=1.5.6.3"
    assert r["endpoint"] == "/wp-admin/admin-ajax.php"
    assert r["action"] == "lakit_ajax"
    assert r["envelope"] == {"subaction": "register", "id": "0"}
    assert r["role_param"] == "lakit_bkrole" and r["role_value"] == "administrator"
    assert r["extra_params"] == {"lakit_field_log": "yes", "lakit_field_pwd": "yes",
                                  "lakit_field_cpwd": "yes"}
    assert r["nonce_from"] == {"url": "/", "key": "ajaxNonce",
                               "object": "LaStudioKitSettings", "param": "_nonce"}
    assert r["source"] == "registry"
