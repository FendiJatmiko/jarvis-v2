# Roadmap / Pick-up doc — pentest-agent (`freeln`)

**Updated:** 2026-07-23 · **Repo:** `~/WORK/cs-ai/freeln` · **Branch:** `stag-01` · **Version:** `v0.24.0`
**This is the master pick-up doc. In-repo mirror of `~/roadmap.md` — either copy is authoritative; keep them in sync.**
For the current in-flight sub-task (askgeorge SQLi cred crack) see `docs/HANDOFF-sqli-askgeorge.md` inside the repo.

> **New AI agent, read this whole file first.** It is written to be self-contained so you can
> resume without prior conversation context. Do NOT trust older statements you might find
> elsewhere claiming "king-addons isn't in the registry" or "only wpdiscuz + wp-file-manager
> are registered" — those are stale. Section 2 below is the current ground truth.

---

## 0. NEW MACHINE SETUP — do this before anything else

The repo is only part of the picture. Several things this project needs are **NOT in git** and
must be brought over from the old laptop.

### 0.1 Clone + Python env
```bash
git clone <your-remote-or-copy> ~/WORK/cs-ai/freeln    # or rsync the whole dir over
cd ~/WORK/cs-ai/freeln
git checkout stag-01
python3.12 -m venv .venv                                # project is on Python 3.12
source .venv/bin/activate
pip install -r requirements.txt                         # just: requests>=2.25
python3 -m pytest -q                                    # sanity: expect 256 passed
python3 pentest-agent.py --version                      # -> pentest-agent 0.24.0
```

### 0.2 SSH access to the lab host (`server-IOM`)
All lab containers live on **server-IOM** (public IP `89.107.7.109`, host `master1`, user `Fendi`).
On the OLD laptop `~/.ssh/config` has:
```
Host server-IOM
  HostName 89.107.7.109
  User Fendi
  IdentityFile ~/.ssh/id_ed25519
```
Copy that stanza **and the key** `~/.ssh/id_ed25519(.pub)` to the new laptop, then verify:
```bash
ssh -o BatchMode=yes server-IOM 'docker ps --format "{{.Names}}" | grep cve- | sort'
```
You should see 8 `cve-*-wordpress` / `cve-*-mysql` pairs (see §3).

### 0.3 Files NOT in git — copy these from the old laptop's repo root
These are gitignored/untracked working files the tool + docs reference:
| file | why it matters |
|------|----------------|
| `cve-lab.txt` | public-front → creds inventory (see §5) |
| `my_domain.txt` | owned-domain list |
| `current-PA-capabilities.txt` | the capability ledger ("what counts as a shell") |
| `sqli_extract_robust.py`, `sqli_diag.py` | the askgeorge SQLi extractor + diagnostic |
| `sqli-extract-askgeorge.log` | last extraction output (has the recovered hash) |
| `kopirimba_getcreds.py` | re-mint kopirimba admin cred (destructive, see §5) |

### 0.4 (Optional but recommended) bring over Claude's project memory
If you want the assistant to keep its accumulated project memory, copy the whole dir
`~/.claude/projects/-home-jatmikov-WORK-cs-ai-freeln/memory/` to the same path on the new
laptop (the path hash matches as long as the repo stays at `~/WORK/cs-ai/freeln`). Not required
— this roadmap is self-contained — but it preserves the ground-truth notes.

### 0.5 AWS / DNS (only if you touch fronts)
Public fronts are Route53-hosted under AWS account `319287884408` (IAM user `Fendi.jatmiko`) and
routed by a **production** nginx-proxy-manager on server-IOM (`work-nginxproxy-1`, host-networked,
~60 live hosts). **Never edit the prod proxy's DB/config directly** — you add/edit proxy hosts in
the NPM UI yourself; the assistant only supplies exact values. NPM forward port must be the
container's published port (8090/8091/8092/8093…), never 80/443.

---

## 1. What this project is

`freeln` is **pentest-agent** — a WordPress exploitation toolkit. Pipeline:
`RECON → FINGERPRINT → SCAN → MATCH → EXPLOIT → VERIFY → SQLI → TRACK-B`.
It fingerprints a WP target, matches CVEs from the Wordfence feed, and lands **proof-of-exploit**
(webshell / RCE / SQLi) on **user-owned lab targets** to justify hardening production. Authorized;
the user owns every target. Goal is *provable exploitability* to make a DevOps→security career case.

**The one rule the project holds itself to** (from `current-PA-capabilities.txt`):
> Only a populated `confirmed[]` with a live `id` (e.g. `uid=33(www-data)`) counts as "working".
> A MATCH candidate, a SQLi timing delta, or an OOB signal is **NOT** a shell.

---

## 2. GROUND TRUTH (verified 2026-07-23)

### 2.1 Recipe registry (`wp/recipes.py`) — 12 entries after the 2026-07-23 kirki+revslider removal
- **RECIPES (Track A, unauth direct):** `wp-file-manager` (CVE-2020-25213), `wpdiscuz`
  (CVE-2020-24186), `ninja-forms-uploads` (CVE-2026-0740), `simple-file-list` (CVE-2025-34085),
  `breeze` (CVE-2026-3844), `king-addons` (CVE-2025-6327).
- **PRIVESC_RECIPES (Track B, unauth → admin → plugin-zip shell):** `lastudio-element-kit`
  (CVE-2026-0920), `opal-estate-pro` (CVE-2025-6934),
  `essential-addons-for-elementor-lite` (CVE-2023-32243), `king-addons` (CVE-2025-6325).
- **SQLI_RECIPES:** `wp-google-map-plugin` (CVE-2026-2580), `wp-automatic` (CVE-2024-27956).
- **Removed 2026-07-23** (restorable from `docs/RECIPE-STATUS.md`): `kirki` (CVE-2026-8206 —
  precondition-blocked) and `revslider` (CVE-2014-9735 — never landed). Their exclusive engine code
  (kirki OOB `--oob-*` flags + `complete_reset_key`; revslider fingerprinting) was removed too.

### 2.2 Confirmed shells (real targets, live `id` in `~/.cache/pentest-agent/*.json`)
| target | CVE / vector | plugin | track |
|--------|--------------|--------|-------|
| georgeagent.com | CVE-2020-24186 | wpdiscuz | A (unauth comment-image upload) |
| xinference.nzmweb.com | CVE-2020-25213 | wp-file-manager | A |
| **king.ofpweb.com** + localhost:8093 | CVE-2025-6327 **and** CVE-2025-6325 | king-addons | A **and** B |
| kopirimba.xbrlink.com + localhost:8090 | CVE-2023-32243 | essential-addons | B (unauth pw-reset → admin) |
| 15.232.162.164 (AWS micro lab, now OFF) | CVE-2020-25213 | wp-file-manager | A |

**Note (correcting older docs):** the essential-addons landing is **CVE-driven** (the recipe fires
the unauth password-reset itself) — it is *not* a "weak-cred" login. And king-addons **is** in the
active registry and lands on its **public front** `king.ofpweb.com`.

### 2.3 v0.23.0 change (this session, 2026-07-23) — RECON adopts redirects
Bare hostnames used to fail on the HTTPS-forced fronts: `king.ofpweb.com` defaulted to `http://`,
the NPM returned `301 → https`, and the exploit POSTs got replayed as bodyless GETs while the WP
auth cookie was bound to the https `siteurl` → both tracks silently failed. `phase_recon` now reads
the final URL after redirects and, when it lands on a **different origin of the same site**
(http→https or apex↔www), adopts that base_url for every later phase (off-site redirects ignored for
scope safety; a typed path is preserved). Helpers `_adopt_redirect` / `_same_site`, 4 new tests,
suite 270 pass. **Practical result: you can now target a bare hostname** — `python3 pentest-agent.py
king.ofpweb.com` — and it self-upgrades to https.

---

## 3. Lab topology (server-IOM) — verified live 2026-07-23

8 WP container stacks running. Public fronts behind the prod NPM (all **HTTPS-forced**):

| container | port | plugin / CVE | public front | can it land? |
|-----------|------|--------------|--------------|--------------|
| cve-wpdiscuz | 8082 | wpDiscuz CVE-2020-24186 | georgeagent.com | ✅ shell |
| cve-kirki | 8086 | Kirki CVE-2026-8206 | xbrlink.com | ❌ needs ComponentLibrary forgot-pw page (absent) |
| cve-gmap | 8088 | WP Google Maps CVE-2026-2580 | askgeorgeai.com | 🔑 SQLi → admin hash (creds, not shell) — **current task** |
| cve-elementor | 8089 | ad-hoc experiment, no vuln plugin | — | ❌ not a real front |
| cve-essaddons | 8090 | Essential Addons CVE-2023-32243 | kopirimba.xbrlink.com | ✅ shell |
| cve-wpauto | 8091 | WP Automatic CVE-2024-27956 | scope3e.com | ❌ premium plugin not installed |
| cve-breeze | 8092 | Breeze CVE-2026-3844 | www.lander.ofpweb.com | ⏳ ready to land: 2.4.4 vuln + gravatars-local ON + comments open; needs only a hosted callback payload. REAL farm forensic vector. |
| cve-kingaddons | 8093 | King Addons CVE-2025-6327/6325 | **king.ofpweb.com** | ✅ shell (both tracks) |

Torn down (older docs list them as running — they are NOT): revslider:8083, nfu:8084,
lastudio:8085, opalestate:8087.

**Debug access:** plugin source `docker exec cve-<slug>-wordpress sh -c 'grep -rn … /var/www/html/wp-content/plugins/<plugin>'`;
DB `docker exec cve-<slug>-mysql mysql -uroot -proot_secret wordpress -e "…"`.
When a recipe won't land on a fresh container, check the usual lab gotchas first: `permalink_structure`
(must be pretty, not "Plain"), uploads dir owned by `www-data`, and seed ≥1 data row for SQLi.

---

## 4. CURRENT IN-FLIGHT TASK — askgeorgeai.com SQLi → admin creds

Detailed handoff: **`docs/HANDOFF-sqli-askgeorge.md`** (in repo). Short version:

- CVE-2026-2580 unauth time-based blind SQLi on `askgeorgeai.com` (`wp-google-map-plugin` 4.9.1) is
  **confirmed** (+5s SLEEP delta). It is a SQLi, **not a shell**.
- Extraction is **COMPLETE**: `LOGIN = admin`, and the password hash is recovered:
  `HASH = $wp$2y$10$AUR59OCPTtyJCwiYUC.NM.20L0GNwT7wJxmOG0hWih1wcycVuzWLK`
- ⚠️ **This is WordPress 6.8's `$wp$` bcrypt hash, NOT legacy phpass `$P$`.** Do **not** use
  `--format=phpass` / hashcat `-m 400`. Use the modern WordPress `$wp$` mode (verify the exact
  hashcat `-m` on the box). bcrypt cost 10 is slow — a real wordlist+rules run; may not crack.

**Next steps (in order):**
1. Crack `$wp$2y$…` offline with the correct WP-bcrypt hashcat mode + wordlist/rules.
2. If cracked → plaintext into `wp/authshell.py` login → Track-B plugin-zip → shell (same mechanism
   proven on kopirimba / :8090). Then update `current-PA-capabilities.txt` (move askgeorge from
   "NOT A SHELL" only if a real `id` lands; else annotate "creds extracted, hash uncracked (bcrypt)").
3. If it won't crack: the SQLi still proves data exfiltration; document that and move on.

**Toolkit hardening backlog (optional):** generalize `ADMIN_LOGIN`/`ADMIN_HASH` in `wp/sqli.py` to
detect single-user sites / dynamic table prefix instead of the hardcoded `wp_capabilities` JOIN, and
route the extractor through `extract()` (or resolve the nonce itself) so the low-level primitives
aren't called raw. Nonce-expiry risk: `fc-call-nonce` is harvested once at start — if a long run
flips all-false mid-extraction, re-harvest inside the char loop.

---

## 5. Credential / target inventory (from `cve-lab.txt`, `my_domain.txt`)

- georgeagent.com → webshell landed (`wsh_*.php?c=whoami`)
- xbrlink.com → admin : `chime-gracie-portugal-sender-hurley-wanda-winifred`
- xbrlink.com Kirki container → admin / `XssTest#Kirki2026!`
- kopirimba.xbrlink.com → admin : `6Z!Lmz9lPV&i3$PG` (random & never saved — if stale, re-mint with
  `kopirimba_getcreds.py`, which fires the **destructive** essaddons CVE-2023-32243 pw-reset)
- king.ofpweb.com → king-addons, both chains land (tool mints its own rogue admin each run)
- askgeorgeai.com → admin / **`$wp$` hash cracking pending** (§4)
- 8.215.58.186/wp-login.php → admin/admin
- Owned domains: nzmweb.com (+wp-v2, www, stag), energylink.ai (+wp-01), scope3e.com, ofpweb.com,
  georgeagent.com, askgeorgeai.com

---

## 6. Recent commits (`stag-01`)
- `f95a696` feat(recon): adopt http→https/canonical redirect base + v0.23.0  ← this session
- `23f3da9` add eael quickview poc
- `d25dea6` feat(lastudio): CVE-2026-0920 + v0.22.0
- `25146d0` feat(king-addons): CVE-2025-6327 + CVE-2025-6325 + v0.21.0
- `92e8214` feat(kirki): CVE-2026-8206 OOB + v0.19.0
