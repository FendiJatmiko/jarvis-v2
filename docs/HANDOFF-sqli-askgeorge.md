# Handoff — askgeorgeai.com SQLi credential extraction

**Status as of 2026-07-23** · branch `stag-01` · pick-up doc for switching machines
**Master pick-up / new-machine setup doc:** `~/roadmap.md` (portable, outside the repo). Read that first.

---

## One-line summary

The unauthenticated time-based blind SQLi on `askgeorgeai.com` (CVE-2026-2580,
`wp-google-map-plugin` 4.9.1) is **confirmed**, and `user_login` + `user_pass` have
been **fully extracted** char-by-char. Remaining work is **cracking the recovered
hash offline** — and note the hash is WordPress 6.8 **`$wp$` bcrypt, NOT phpass**
(details below). The earlier empty-result / truncation problems are fixed.

## The target

- **Host:** `https://askgeorgeai.com` — WordPress 6.8.3, plugin `wp-google-map-plugin` 4.9.1
- **Vuln:** CVE-2026-2580 — unauth time-based blind SQLi via the `orderby` sink.
  - nopriv `admin-ajax` action `wpgmp_ajax_call` → `check_ajax_referer('fc-call-nonce','nonce')`
    → `operation=wpgmp_processor` + `page=wpgmp_manage_map` reaches
    `prepare_items()`, whose raw `order by {orderby}` runs **pre-auth**.
  - Request is a **POST** but the sink reads **`$_GET`** → recipe uses
    `method:POST` + `inject_in:params`.
  - The `fc-call-nonce` is localized as `nonce` on the frontend and harvested from `/`.
- **Confirmed live:** control ~0.43s vs injected ~5.2s on `SLEEP(5)` — clean +5s delta.
- This is **NOT a shell.** Per `current-PA-capabilities.txt` it yields no login/no
  access on its own. The whole point of this effort is to squeeze creds out of it.

## Files involved (all in repo root)

| File | Role |
|------|------|
| `wp/sqli.py` | SQLi engine: `confirm()`, `extract()`, primitives `_bit_true`/`_extract_char`, `_resolve_nonce()`. Convenience exprs `ADMIN_LOGIN`/`ADMIN_HASH`. |
| `wp/recipes.py` | `SQLI_RECIPES` — the `wp-google-map-plugin` CVE-2026-2580 recipe (~line 478). |
| `sqli_diag.py` | Diagnostic — probes query pieces separately (count_users, first_login, count_admins, cap_prefix). |
| `sqli_extract_robust.py` | **The extractor.** Single-user-site approach, jitter-hardened. This is the one to run. |
| `sqli-extract-askgeorge.log` | Latest run output. |

## What the diagnostic found (2026-07-22)

Running `sqli_diag.py`:

```
[count_users]  = '1'     <- single-user site
[first_login]  = 'a'     <- username starts 'a', truncated by jitter
[count_admins] = '0'     <- the admin JOIN matches ZERO rows  <-- root cause
[cap_prefix]   = ''      <- couldn't recover capabilities meta_key
```

**Two root causes identified:**

1. **Empty result cause:** `wp/sqli.py`'s `ADMIN_LOGIN`/`ADMIN_HASH` convenience
   expressions JOIN `wp_usermeta` on `meta_key='wp_capabilities' AND meta_value
   LIKE '%administrator%'`. On this site that matches **0 rows** (`count_admins=0`),
   so the original run printed `admin user_login = ''`.
   **Fix:** it's a single-user site — skip the JOIN, query `wp_users LIMIT 1`
   directly (the lone user is necessarily the admin). This is what
   `sqli_extract_robust.py` does.

2. **Jitter/truncation cause:** standard `extract()` stops at the first NUL, and a
   timing false-negative looks like a NUL → truncates (`first_login='a'`).
   **Fix:** `sqli_extract_robust.py` binary-searches `LENGTH()` first, then
   extracts exactly N chars, verifying each with an equality-SLEEP and retrying
   (DELAY=4, MARGIN=1.5, TRIES=4).

## The bug I fixed today (nonce)

`sqli_extract_robust.py` called the low-level primitives `_bit_true` /
`_extract_char` **directly**. Those do **not** resolve the nonce — only
`confirm()` and `extract()` call `_resolve_nonce()`. Result: no `fc-call-nonce`
sent → `check_ajax_referer` fails → SLEEP never fires → every LENGTH/char read as
0 (`length = 0`, empty output).

**Fix applied** (top of `sqli_extract_robust.py`, after loading the recipe):

```python
r = S._resolve_nonce(BASE, http, r)
```

Verified: nonce harvests (e.g. `46bc62cdf9`), `LENGTH>0` returns True, `LENGTH>60`
returns False. Discrimination is correct.

## How to run (any machine)

```bash
cd <repo>                      # freeln checkout
source .venv/bin/activate      # py3.12, needs `requests`
python -u sqli_extract_robust.py 2>&1 | tee sqli-extract-askgeorge.log
```

It's **slow** (time-based, ~4s per bit, ~7 bits/char + verify + retries). Expect
tens of minutes: `user_login` first, then the 63-char `$wp$` bcrypt `user_pass`
hash (NOT a 34-char phpass hash — WP 6.8 changed the format; see below).

## Result of this run (COMPLETE, 2026-07-22)

- `LOGIN = admin`
- `HASH  = $wp$2y$10$AUR59OCPTtyJCwiYUC.NM.20L0GNwT7wJxmOG0hWih1wcycVuzWLK`

⚠️ **Hash format is WP 6.8 `$wp$` bcrypt, NOT legacy phpass `$P$`.** WordPress 6.8
moved to bcrypt (`$wp$2y$10$…`): it base64-encodes an HMAC-SHA384 of the password,
then bcrypts that. Cost factor here is 10.

## Next steps after extraction

1. **Crack the hash offline.** It is **`$wp$` bcrypt**, not phpass — do NOT use
   `--format=phpass` / hashcat `-m 400`. Use the current WordPress `$wp$` mode
   (verify the exact hashcat `-m` on the box; it's the modern WP bcrypt mode).
   bcrypt cost 10 is slow — a real wordlist+rules run, and it may not crack at all
   if the password is strong.
2. **Feed the credential attack.** Cracked plaintext → `wp/authshell.py` login →
   Track-B plugin-zip upload for a shell (same mechanism proven on kopirimba /
   localhost:8090).
3. **Nonce expiry risk:** the nonce is harvested once at start. If a long run
   starts failing (bits flip to all-false mid-extraction), the `fc-call-nonce`
   likely rotated — re-run, or add periodic re-harvest inside the char loop.
4. Consider generalizing `ADMIN_LOGIN`/`ADMIN_HASH` in `wp/sqli.py` to detect
   single-user sites / dynamic table prefix instead of the hardcoded `wp_` JOIN.

## Cross-refs (project memory)

- `current-PA-capabilities.txt` — ground-truth capability ledger; askgeorge listed
  under "NOT A SHELL". Update it if/when creds land.
- `cve-lab.txt`, `my_domain.txt` — target/credential inventory (askgeorge is a
  user-owned lab target).
- Memory: `farm-real-attack-surface`, `cve-lab-topology`.
