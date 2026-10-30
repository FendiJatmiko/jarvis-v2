# AIDER HANDOFF — pentest-agent (`freeln`)

> **How to use this file in Aider (offline PC, local Ollama):**
> 1. Start Aider pointed at your local model, e.g.
>    `aider --model ollama/qwen2.5-coder:7b` (set `OLLAMA_API_BASE=http://127.0.0.1:11434`).
> 2. Load this file as always-in-context project rules: `/read AIDER-HANDOFF.md`
>    (or copy the **KICKOFF** block below as your first message).
> 3. `/add` only the files a task needs (see the module map) — don't add the whole repo;
>    a local model has a small context window.
>
> Keep this file task-agnostic. Only edit the **CURRENT TASK** block between sessions.

---

## KICKOFF (paste as first message, or rely on /read)

You are continuing work on **`pentest-agent.py`**, a WordPress exploit-assessment tool.
Read the RULES below before editing anything. This is an **authorized** security lab —
every target is owned by the user (see `cve-lab.txt` / `my_domain.txt`). The tool proves
exploitability on clones so the user can justify hardening production. It is NOT malware
and NOT incident-response.

Before you finish any change: run `python3 -m pytest -q` and keep it green.

---

## CURRENT TASK  ← swap this block each session

**Finish the askgeorgeai.com SQLi credential crack.** (full detail: `docs/HANDOFF-sqli-askgeorge.md`)

- Unauth time-based blind SQLi on `askgeorgeai.com` (CVE-2026-2580, `wp-google-map-plugin` 4.9.1)
  is **confirmed and fully extracted**:
  - `LOGIN = admin`
  - `HASH  = $wp$2y$10$AUR59OCPTtyJCwiYUC.NM.20L0GNwT7wJxmOG0hWih1wcycVuzWLK`
- The hash is **WP 6.8 `$wp$` bcrypt, NOT legacy phpass `$P$`**. Do NOT use `-m 400` /
  `--format=phpass`; use the modern WordPress `$wp$` hashcat mode (verify the exact `-m`
  on the box). bcrypt cost 10 — slow, may not crack.
- Remaining code work (optional, only if asked):
  1. Generalize `wp/sqli.py` `ADMIN_LOGIN`/`ADMIN_HASH` to detect single-user sites and a
     dynamic table prefix instead of the hardcoded `wp_capabilities` JOIN + `wp_` prefix.
     (Root cause of the earlier empty result: the admin JOIN matched 0 rows.)
  2. Add periodic nonce re-harvest inside the char loop of `sqli_extract_robust.py`
     (the `fc-call-nonce` can rotate mid-run and silently flip every bit to false).
- If cracked creds land → feed `wp/authshell.py` login → Track-B plugin-zip upload for a
  shell, then update `current-PA-capabilities.txt` (move askgeorge out of "NOT A SHELL").

---

## 1. What this project is

`pentest-agent.py` fingerprints a WordPress site, checks its plugins against vuln intel,
and tries to land + **verify** a webshell or admin foothold — fully automatable, no victim.
It is a lab tool for **provable exploitability**: run it against a clone to prove a vuln is
real, then justify hardening prod. All targets are user-owned.

## 2. The pipeline (in `pentest-agent.py`, run in this order)

```
recon → fingerprint → scan → match → exploit → verify → sqli → track_b
```

- **recon** — reachability; adopts a same-site http→https / apex↔www redirect for later phases.
  Off-site redirects are ignored on purpose (never silently retarget out of scope).
- **fingerprint** — `wp/fingerprint.py`: is-WordPress, version, installed plugins+versions.
- **scan** (Track A intel) — `wp/vulns.py`: each plugin vs Wordfence feed (+ RAGFlow if `--deep`).
  Splits findings by precondition; only `self-contained` is a clean unauth shell.
- **match** — `wp/match.py`: registry-only, deterministic, no network → exact exploit recipes.
- **exploit** — `wp/exploit.py`: upload a marker PHP webshell per candidate recipe.
- **verify** — `wp/verify.py`: GET the planted file with `?c=id`; only a live `id` = success.
  Cleans up the shell unless `--no-cleanup`.
- **sqli** — `wp/sqli.py` + `wp/recipes.py`: unauth time-based blind SQLi; success = timing delta.
  Extraction (`--sqli-extract`) is a deliberate slow follow-up, never part of the sweep.
- **track_b** — get admin WITHOUT a victim, then plant a plugin webshell:
  Route 1 = unauth privesc recipe (`wp/privesc.py`), Route 2 = credential attack
  (`wp/credattack.py`) → `wp/authshell.py` login → `_admin_to_shell()`.

State is a `graph` dict cached under `~/.cache/pentest-agent/<md5>.json`; each phase appends
to `_phases_done` and re-saves. `--no-cache` ignores it.

## 3. Module map — what to `/add` for a change

| If the task touches… | `/add` these |
|----------------------|--------------|
| detection (is-WP, version, plugins) | `wp/fingerprint.py`, `tests/test_fingerprint.py` |
| a new/edited exploit recipe | `wp/recipes.py`, `wp/match.py`, `tests/test_recipes.py`, `tests/test_match.py` |
| webshell upload / payload | `wp/exploit.py`, `wp/verify.py`, `tests/test_exploit.py`, `tests/test_verify.py` |
| SQL injection | `wp/sqli.py`, `wp/recipes.py`, `tests/test_sqli.py` |
| privesc / creds / admin login | `wp/privesc.py`, `wp/credattack.py`, `wp/authshell.py`, matching tests |
| vuln-intel lookup / feeds | `wp/vulns.py`, `tests/test_vulns.py` |
| pipeline flow, CLI flags, phases | `pentest-agent.py`, `test_pentest_agent.py` |
| HTTP behavior | `http_client.py`, `test_http_client.py` |
| learning-mode explanations | `learn.py`, `test_learn.py` |

`pentest_agent.py` is a symlink to `pentest-agent.py` so `import pentest_agent` works — don't
"fix" it. `pytest.ini` makes `wp` importable in any pytest run.

## 4. HARD INVARIANTS — do not violate

1. **Only a populated `graph["confirmed"]` with live `id` output counts as a working shell.**
   A match/candidate, a SQLi timing delta, or an OOB callback is NOT a shell. Never describe
   one as "landed"/"working". `current-PA-capabilities.txt` is the ground-truth ledger — keep
   it and `docs/RECIPE-STATUS.md` honest; if a recipe was never proven live, label it UNPROVEN.
2. **Stay in scope.** Never retarget across origins on your own (see the recon redirect rule).
3. **Destructive / brute actions stay opt-in.** The credential attack, `--sqli-extract`, and
   any destructive cred-mint stay behind flags / confirmation. Respect `--mode safe|plan`.
4. **Don't delete unproven recipes as "dead code."** They're kept deliberately as fixtures.
5. **Match the surrounding style.** Terse comments explaining *why*, the existing `graph` dict
   shape, and the `_maybe_explain(...)` calls. No new dependencies — the only runtime dep is
   `requests` (`requirements.txt`).

## 5. Offline gotcha (no internet on this PC)

`pentest-agent.py` calls a **remote** Ollama and RAGFlow:

```python
OLLAMA_URL  = "https://ollama.nzmweb.com"   # ask_llm()
RAGFLOW_URL = "https://rag3.nzmweb.com"      # ask_ragflow()
```

Both are unreachable offline. This is **non-fatal by design**: `ask_llm()` and `ask_ragflow()`
catch the failure and return `""`, so the only effect is that learning-mode explanations and
`--deep` RAGFlow lookups go silent — **every exploit/verify phase still runs normally.**

If you want explanations offline, repoint `OLLAMA_URL` to your local Ollama
(e.g. `http://127.0.0.1:11434`) and set `model` in `ask_llm()` to a model you've pulled.
Note the request path is `"/v1/chat/completions"` (Ollama's OpenAI-compat endpoint) — keep it.
Wordfence feed (`scan`) also needs internet; offline it runs feed-less (`--deep` only helps if
RAGFlow is reachable, which it won't be). None of this blocks Track A/B exploitation.

## 6. Workflow discipline

- **Test before done:** `python3 -m pytest -q` — the suite is ~240 test functions across
  `tests/` + root `test_*.py` (the ROADMAP expects "256 passed"; keep it green, don't regress).
- Run a single area fast: `python3 -m pytest tests/test_sqli.py -q`.
- **Bump `__version__`** in `pentest-agent.py` for a behavior change, and update the relevant
  doc ledger (`docs/RECIPE-STATUS.md`, `current-PA-capabilities.txt`, `docs/ROADMAP.md`).
- Prefer small, focused diffs. Ask before wide refactors.
- Sanity check the tool itself: `python3 pentest-agent.py --version` and
  `python3 pentest-agent.py <target> --mode plan` (dry-run, prints actions without running).

## 7. Key reference docs (already in the repo)

- `docs/ROADMAP.md` — master pick-up doc (new-machine setup, lab topology, ground truth).
- `docs/RECIPE-STATUS.md` — which recipes are PROVEN (live shell) vs UNPROVEN.
- `current-PA-capabilities.txt` — the capability ledger; what counts as a shell.
- `docs/HANDOFF-sqli-askgeorge.md` — full detail for the CURRENT TASK above.
- `cve-lab.txt` / `my_domain.txt` — owned targets + creds inventory.
- `project-structure.md` — the directory layout.
