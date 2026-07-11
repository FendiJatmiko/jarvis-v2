# WordPress Farm Defense Toolkit — Reference

> Everything the toolkit does today, and what every option means.
> Branch: `exploit-chain` · pentest-agent `v0.11.0`
> **Authorized defensive use only** (your own / your clients' assets).

---

## 1. The mental model (how the pieces fit)

```
                 WHOLE INTERNET                    ONE SITE
                 (wide, shallow)                   (narrow, deep)

  scanner_dork.py  ──────────►  agent_bridge  ──────────►  pentest-agent.py
  "which of MY sites are         (--exploit flag,          "what EXACTLY is on
   exposed, and how?"             owned-only)               this site, can I get
   via Shodan's index                                       a shell?" — live probes

  attack_walk.sh  ── manual, hands-on demonstration of the initial-access
                     playbook for a single exposed host (teaching / boss demo)
```

- **`scanner_dork.py`** = *discovery*. Reads Shodan's pre-built index, flags which of your assets surface under exposure categories. Cheap (query credits). Cannot see plugin versions.
- **`pentest-agent.py`** = *inspection + exploitation*. Given one URL, actively fingerprints the site, matches plugin CVEs, and (in `auto`) attempts the webshell chain. Deep, live.
- **`agent_bridge.py`** = glue. The `--exploit` flag on the scanner hands your surfaced hosts to pentest-agent.
- **`attack_walk.sh`** = a manual, transparent walk of the attacker's initial-access steps for `exposed_listings` / `login_surfaces` / `exposed_databases`.

**Rule of thumb:** scanner_dork finds *targets*; pentest-agent gets *shells*; attack_walk *explains* the config-exposure paths.

---

## 2. `scanner_dork.py` — internet-wide exposure scanner

Runs unscoped fingerprint dorks, harvests every host that surfaces, and (with `--mine`) flags which are yours.

### Engines (`--engine`)

| Engine | Auth (env var) | Notes |
|--------|----------------|-------|
| `shodan` | `SHODAN_API_KEY` | **Primary.** Search API needs a paid membership + query credits. `--exploit` works only here. |
| `netlas` | `NETLAS_API_KEY` | Free-tier search available. |
| `censys` | `CENSYS_PAT` (+ `CENSYS_ORG_ID`/`--org`) | Censys Platform (CenQL). |
| `google` | `GOOGLE_API_KEY` + `GOOGLE_CX` | Supplementary; Google restricts internet-wide search. |

Default engine is `netlas`. Pass `--engine shodan` for the real thing.

### Categories (the 8 things it hunts) & danger

| Category | What a hit means | Danger |
|----------|------------------|--------|
| `wordpress_hosts` | Runs WordPress + is reachable | 3 — baseline, everyone shows here |
| `login_surfaces` | `xmlrpc.php` / phpMyAdmin exposed | 2 — attack surface open |
| `exposed_listings` | Directory listing / backups readable | 1 — trivial takeover (leaked creds) |
| `exposed_databases` | MySQL/Postgres/Redis/Mongo/Elastic on public port | 1 — trivial takeover |
| `admin_panels` | Adminer/cPanel/Webmin internet-facing | 1–2 — control plane exposed |
| `unfinished_install` | WP install wizard reachable | 0 — one-click takeover |
| `injected_gambling` | `slot`/`judi` markers | **0 — already breached** |
| `compromised_markers` | Live webshell panels (WSO/IndoXploit/b374k), pharma | **0 — already breached** |

Lower number = closer to compromise. A well-secured farm should surface **only** in `wordpress_hosts`.

### CVE hints
Each finding is annotated with Shodan's own signals when present:
`[nginx 1.18.0 | possible CVE-2021-23017, CVE-2018-15473]`.
These are **infrastructure** CVEs (web server / SSH / PHP / DB), inferred from banners — **not** WordPress plugin CVEs, and "possible" because version-based. Plugin-CVE truth only comes from pentest-agent.

### Options

| Option | Meaning |
|--------|---------|
| `--engine {shodan,google,censys,netlas}` | Which source to query (default `netlas`). |
| `--mine FILE` | File of YOUR domains/IPs/CIDRs to flag in results. Omit = harvest-only. See §6. |
| `--pages N` | Result pages per query (default 2). Each page = 1 query credit. |
| `--country XX` | 2-letter code to scope the harvest (e.g. `ID`). |
| `--net NET` | Scope to CIDR(s): one, comma-list, or a wordlist file (e.g. `id.zone`). shodan/censys/netlas only. |
| `--net-batch N` | Max CIDRs OR'd per query (default 10); big `--net` lists split into chunks. |
| `--cn NAME` | Find your own estate by TLS cert CN / DNS name. |
| `--org ID` | Censys Organization ID (or `CENSYS_ORG_ID`). |
| `--query Q` | Censys: raw CenQL passthrough. |
| `--only CATS` | Comma-separated categories to run (subset of the 8 above). |
| `--test` | Shodan: validate key + show plan/credits, then exit. |
| `--delay S` | Seconds between API calls (default 1.0). |

### `--exploit` chaining options (Shodan only)

| Option | Meaning |
|--------|---------|
| `--exploit` | After the scan, hand YOUR surfaced hosts to pentest-agent. **Requires `--mine`.** OFF by default. |
| `--exploit-mode {auto,plan,safe}` | Mode passed to pentest-agent (default `auto`). |
| `--exploit-dry-run` | List the hosts that would be exploited, run nothing. |
| `--agent-path PATH` | Path to pentest-agent (default `./pentest-agent.py`). |
| `--exploit-timeout SECS` | Per-host timeout (default 600). |

**Safety invariant:** only `--mine`-matched (owned) hosts are ever exploited — the raw harvested internet pile is never touched. `--exploit` refuses to run without `--mine`.

### Output
Writes `scan-<timestamp>.md` (human) and `scan-<timestamp>.json` (machine). Each of your hits shows host, category, the dork that found it, the scheme+port URL, and any CVE hints. With `--exploit`, an `## Exploitation pass` section / `exploit_results[]` is appended.

### Examples
```bash
export SHODAN_API_KEY=...
python3 scanner_dork.py --engine shodan --test                              # validate key + credits
python3 scanner_dork.py --engine shodan --mine domains.txt --country ID     # scan Indonesia, flag yours
python3 scanner_dork.py --engine shodan --mine domains.txt --net id.zone     # scope to your CIDRs
python3 scanner_dork.py --engine shodan --mine domains.txt --only login_surfaces,exposed_databases
python3 scanner_dork.py --engine shodan --mine domains.txt --exploit --exploit-dry-run   # preview chain
```

---

## 3. `pentest-agent.py` — WordPress webshell + privesc agent

Given one authorized WordPress target, runs a 7-phase pipeline. **v0.11.0.**

### Pipeline
`RECON → FINGERPRINT → SCAN → MATCH → EXPLOIT → VERIFY → TRACK-B`

| Phase | Does |
|-------|------|
| RECON | One HTTP GET — confirm the server is up right now. |
| FINGERPRINT | Detect WordPress + enumerate installed **plugins & versions** (home-page scrape + `readme.txt` probing). |
| SCAN | Match installed plugins against the Wordfence vuln feed (`--deep` also checks RAGFlow). Webshell-focused classification. |
| MATCH | Pair vulnerable plugins with known exploit recipes. |
| EXPLOIT | Run the matched recipe → plant a marker webshell. |
| VERIFY | Confirm command execution (`✅ WEBSHELL CONFIRMED`). |
| TRACK-B | Authenticated chain: privesc/weak-login → admin → plugin-upload webshell (`✅ WEBSHELL via …`). |

**Track A** = detection (SCAN, data-driven). **Track B** = the authenticated exploit chain.

### Exploit recipes it actually knows (code, not fabricated)

| Plugin | CVE | Affected | Kind |
|--------|-----|----------|------|
| wp-file-manager | CVE-2020-25213 | ≤6.8 | unauth file upload → RCE |
| wpdiscuz | CVE-2020-24186 | 7.0.0–7.0.4 | unauth file upload → RCE |
| lastudio-element-kit | CVE-2026-0920 | ≤1.5.6.3 | unauth privesc → admin (Track B) |

Track B also has generic routes (register-role / options-update / auth-bypass / password-reset) and a **wp-login credential attack** (common passwords).

### Modes (`--mode`)
- `auto` (default) — attempts the full chain (plants shells, tries logins).
- `safe` — confirms each action before doing it.
- `plan` — recon + CVE match only, **no exploitation**.

### Options

| Option | Meaning |
|--------|---------|
| `target` | IP, host, or URL of an AUTHORIZED WordPress site. `https://` scheme is preserved. |
| `--mode {auto,safe,plan}` | Aggressiveness (see above). |
| `--quiet` | Disable learning-mode explanations. |
| `--no-cleanup` | Keep the planted webshell (default cleans up). |
| `--no-cache` | Ignore saved state (cache is per-target). |
| `--deep` | SCAN: also RAGFlow-check plugins absent from the Wordfence feed (slower). |
| `--no-track-b` | Skip the authenticated chain entirely. |
| `--no-brute` | Track B: skip the wp-login credential attack (privesc recipes only). |
| `--wordlist PATH` | Track B: extra passwords / `user:pass` pairs for the credential attack. |
| `--verbose` | SCAN: list every out-of-scope finding instead of a one-line summary. |
| `--version` | Print version and exit. |

### Environment
`WORDFENCE_API_KEY` (SCAN feed, cached at `~/.cache/pentest-agent/`). RAGFlow/Ollama endpoints are configured in-file.

### Examples
```bash
python3 pentest-agent.py https://site.tld                 # full pipeline, learning mode
python3 pentest-agent.py https://site.tld --mode plan      # detect only, no exploit
python3 pentest-agent.py https://site.tld --no-track-b     # Track A + direct-CVE exploit only
python3 pentest-agent.py https://site.tld --no-cleanup     # leave the shell for inspection
```

---

## 4. `agent_bridge.py` — the recon→exploit glue

Not run directly; invoked by `scanner_dork --exploit`. Pure, unit-tested functions:

| Function | Role |
|----------|------|
| `dedupe_targets(your_hits)` | Collapse hits → one entry per host (merges categories). |
| `build_argv(url, mode, agent_path)` | The exact pentest-agent command. |
| `parse_verdict(stdout, rc)` | `shell` / `error` / `clean` — read from stdout markers (pentest-agent always exits 0). |
| `run_exploitation(...)` | Sequential fan-out over owned hosts; one failure never aborts the sweep; `dry_run` spawns nothing. |
| `write_exploit_report(ts, results)` | Fold results into the scan report. |

---

## 5. `attack_walk.sh` — manual attacker's-eye walkthrough

Hands-on demonstration of initial access for one host. **Read-only by default.**

```bash
./attack_walk.sh <url|host> [--loud] [-V|--verbose] [--db | --db-host=HOST]
```

| Flag | Meaning |
|------|---------|
| (default) | Read-only recon; prints `[safe]` / `[HIT ]` findings only. |
| `--loud` | Add the noisy/exploit steps: pull creds from a leaked backup, xmlrpc multicall brute, DB trust-login proofs. |
| `-V`, `--verbose` | Show OBJECTIVE / WHY / FIX per step + a remediation summary. |
| `--db` | Enable PHASE C (probe DB ports on the target host). |
| `--db-host=HOST` | PHASE C against a different IP (implies `--db`). |

**Phases:** A = `exposed_listings` (dir listings, backups, credential extraction). B = `login_surfaces` (xmlrpc alive/methods, username enumeration, phpMyAdmin, multicall brute). C = `exposed_databases` (postgres/mysql/redis/mongo/elastic reachability + unauth/trust proofs).

```bash
./attack_walk.sh https://clone.example.com -V                 # safe demo w/ explanations
./attack_walk.sh https://clone.example.com --db --loud -V     # full walk on a clone
```

---

## 6. `--mine` file format (accepted by scanner_dork)

One entry per line; `#` comments and blanks ignored. Six shapes, mix freely:

| Shape | Example | Matches |
|-------|---------|---------|
| bare domain | `example.com` | itself **and any subdomain** |
| subdomain | `shop.example.com` | exactly |
| bare IPv4/IPv6 | `203.0.113.10` | that IP (stored /32 or /128) |
| CIDR | `203.0.113.0/24` | any IP in the block |
| scheme-prefixed | `https://portal.example.com` | scheme stripped → host |
| host + path | `example.com/wp-admin` | path dropped → host |

**Do NOT add a `:port`** — it's swallowed as junk and never matches. The port lives on the harvested side; the scanner reports it for you. See `domains.txt.example`.

---

## 7. Environment variables (all keys, one place)

| Variable | Used by | For |
|----------|---------|-----|
| `SHODAN_API_KEY` | scanner_dork | Shodan search (paid plan + credits) |
| `NETLAS_API_KEY` | scanner_dork | Netlas engine |
| `CENSYS_PAT` / `CENSYS_ORG_ID` | scanner_dork | Censys engine |
| `GOOGLE_API_KEY` / `GOOGLE_CX` | scanner_dork | Google engine |
| `WORDFENCE_API_KEY` | pentest-agent | SCAN vuln feed |

---

## 8. Common workflows

**A. See what an attacker sees about your farm (safe):**
```bash
python3 scanner_dork.py --engine shodan --mine domains.txt --country ID
```

**B. Deep-inspect one flagged site, no exploitation:**
```bash
python3 pentest-agent.py https://flagged-site.tld --mode plan
```

**C. Full auto chain across owned hits (preview first!):**
```bash
python3 scanner_dork.py --engine shodan --mine domains.txt --exploit --exploit-dry-run
python3 scanner_dork.py --engine shodan --mine domains.txt --exploit          # then for real
```

**D. Understand a specific exposure hands-on (on a clone):**
```bash
./attack_walk.sh https://clone.tld --db --loud -V
```

---

## 9. Honest limitations

- **scanner_dork sees exposure, not plugin CVEs.** Shodan can't enumerate WP plugins. The CVE hints are infra-level and "possible."
- **`--exploit` matches the scanner category ≠ what it exploits.** pentest-agent runs its own pipeline; an `exposed_listings`/`exposed_databases` hit usually returns "no webshell path" unless the host independently has a plugin CVE or weak login. `exposed_databases` needs the psql/redis path (attack_walk PHASE C), not pentest-agent.
- **Exploit coverage = 3 recipes** (2 direct + 1 privesc). Detection is broad (the whole feed); exploitation is only what's coded.
- **attack_walk `--loud` is intrusive** — clone/owned only; credential attacks can lock accounts on live sites.
- **Shodan search needs a paid plan.** A free key does `--test` only.
