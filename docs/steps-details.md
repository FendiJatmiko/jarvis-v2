Good, this confirms my understanding. Now I have everything needed to give an accurate, grounded breakdown.

pentest-agent.py as 8 independent steps

Each step reads the graph state left by the previous one and writes its own — that's literally the graph dict threaded through main(). Here's the pipeline decomposed:

1. Target parsing — parse_target()
   Turn whatever you typed (10.0.0.5, https://site.tld/blog) into a normalized {base_url, host}. Not really "recon" yet — just input normalization.

2. RECON — phase_recon()
   One GET /. Only asks: is anything alive here? Even a 500 counts as "reachable" (the server responded). This is the cheapest possible liveness check before spending time on anything else.

3. FINGERPRINT — phase_fingerprint()
   Confirm it's WordPress, get the core version, and enumerate installed plugins (passive home-page scraping + active readme.txt probing against a list of known-vulnerable slugs — this is also how it catches plugins that don't show up
   passively, like admin-only ones).

4. SCAN — phase_scan()
   For every plugin+version found, look it up against vuln intel (Wordfence feed first, RAGFlow fallback if --deep). This is where the three-tier triage happens: inscope (auto-exploitable webshell/privesc), chain (plausible but needs a
   victim/foothold — XSS/CSRF/SQLi/IDOR), out (irrelevant). Nothing is exploited here — it's classification only.

5. MATCH — phase_match()
   Take the inscope findings from SCAN and match them against the local recipe registry (wp_recipes.py) — i.e., "we know a vuln exists, do we actually have a working exploit recipe for it?" Populates candidates.

6. EXPLOIT — phase_exploit()
   Track A — direct unauthenticated webshell. Fires the matched recipe's payload (file-upload/RCE-class bugs) and plants a shell, no login involved.

7. VERIFY — phase*verify()
   The trust boundary of the whole tool: hit the planted shell's marker (?c=id → WSH*<token>\_START...END) and confirm actual command execution happened — not just "the upload returned 200." Anything not verified here doesn't get called a
   win.

8. TRACK-B — phase_track_b()
   Track B — admin-first path, for when there's no direct webshell recipe but there is a path to admin. Two sub-routes tried in order, both fully automatable (no victim):

- 8a. Privesc recipe (register-role / options-update / auth-bypass / password-reset) → admin session or creds → log in if needed.
- 8b. Fallback: credential attack against wp-login.php (weak/common passwords, capped attempts).

  Either way, once admin is reached: plant a plugin webshell, then loop back through the same VERIFY logic (\_admin_to_shell calls wp_verify.verify directly) before declaring success.

---

The shape of it

parse → RECON → FINGERPRINT → SCAN → MATCH → EXPLOIT → VERIFY → TRACK-B
│ │ │ │ │ │ │
alive? is it WP? classify have a plant confirm admin-first + plugins 3 tiers recipe? shell exec fallback

Two things make this not-quite-linear:

- SCAN and TRACK-B share a success criterion (VERIFY's marker-based confirmed-exec check) — Track A and Track B both terminate at the same bar, they just take different roads to get there.
- Every phase is idempotent/resumable — each one appends its name to \_phases_done and calls \_save_state, which is what backs --no-cache/resume behavior.

So: 7 pipeline phases + 1 pre-step (target parsing) = 8 steps, with step 8 internally branching into 2 sub-routes (2a/2b). If you count those sub-routes as their own steps, it's 9.
