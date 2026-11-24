# WordPress Farm Defense Toolkit

See your WordPress estate the way an attacker does — **discover** exposed sites internet-wide, **inspect** them for real vulnerabilities, and **demonstrate** exactly how a compromise happens, so you can shut it before a gambling-injection crew finds it first.

> ⚠️ **Authorized defensive use only.** Run against your own / your clients' assets, or a clone.

## The three tools (one line each)

| Tool | Does |
|------|------|
| **`scanner_dork.py`** | Internet-wide *discovery* — asks Shodan which of your sites are exposed, and how. |
| **`pentest-agent.py`** | Per-site *inspection + exploitation* — fingerprints one site, matches plugin CVEs, attempts the webshell chain. |
| **`attack_walk.sh`** | Manual *demonstration* — walks the initial-access steps for one exposed host (great for understanding + showing your boss). |

They chain: **`scanner_dork` finds targets → `pentest-agent` gets shells** (via the `--exploit` flag). `attack_walk` explains the config-exposure paths by hand.

## 30-second quickstart

```bash
pip install -r requirements.txt

# 1. Find your exposure (needs a paid Shodan key). List your assets in domains.txt first.
export SHODAN_API_KEY=...
python3 scanner_dork.py --engine shodan --test                            # validate key + credits
python3 scanner_dork.py --engine shodan --mine domains.txt --country ID   # scan + flag YOUR sites
#   → writes scan-<timestamp>.md / .json

# 2. Deep-inspect one flagged site — detect only, no exploitation:
python3 pentest-agent.py https://flagged-site.tld --mode plan

# 3. Understand one exposure hands-on (on a clone):
./attack_walk.sh https://clone.tld --db --loud -V
```

Build your `domains.txt` from `domains.txt.example` (it documents all accepted formats: domains, IPs, CIDRs, …).

## Full documentation

📖 **[`docs/TOOLKIT.md`](docs/TOOLKIT.md)** — every capability and every option: all 8 scanner categories with danger levels, the 7-phase pentest-agent pipeline, exploit recipes, the `--exploit` chaining, the `--mine` format, all environment variables, common workflows, and honest limitations.

## Requirements

- Python 3, `requests` (`pip install -r requirements.txt`)
- API keys per engine — `SHODAN_API_KEY` (primary; paid search plan), optionally `NETLAS_API_KEY`, `CENSYS_PAT`, `GOOGLE_API_KEY`+`GOOGLE_CX`
- `WORDFENCE_API_KEY` for pentest-agent's vulnerability SCAN
- For `attack_walk.sh --db --loud`: `psql` / `mysql` / `redis-cli` clients (optional; reachability checks need none)

## The one thing to remember

`scanner_dork` sees **exposure** (Shodan's coarse index); `pentest-agent` sees the **deep truth** (live plugin versions + real CVEs). A scanner category hit is a *lead*, not a verdict — and it isn't necessarily what pentest-agent can exploit. See §9 of the TOOLKIT for the traps.
