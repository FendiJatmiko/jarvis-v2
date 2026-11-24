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

## Project Structure

The codebase is organized into logical modules for clarity and maintainability:

```
jarvis-v2/
├── src/                          # Main application source code
│   ├── agents/                   # Autonomous penetration testing agents
│   │   ├── pentest-agent.py     # Core agent: 7-phase WordPress assessment
│   │   ├── pentest-ai.py        # AI-powered analysis tool (RAGFlow + LLM)
│   │   └── agent_bridge.py      # CLI bridge for operator-facing integration
│   │
│   ├── utils/                    # Utility & helper modules
│   │   ├── http_client.py       # HTTP session management + requests
│   │   ├── recon.py             # Host reconnaissance (nmap, service detection)
│   │   ├── scanner_dork.py      # Internet-wide discovery (Shodan, Netlas, Censys)
│   │   ├── learn.py             # Knowledge base & learning utilities
│   │   └── setup_ragflow.py     # RAGFlow initialization & configuration
│   │
│   └── wp/                       # WordPress exploitation framework (12 modules)
│       ├── exploit.py           # Webshell deployment & payload generation
│       ├── privesc.py           # Privilege escalation chains
│       ├── sqli.py              # SQL injection detection & extraction
│       ├── authshell.py         # Authentication & shell establishment
│       ├── fingerprint.py       # WordPress version & plugin detection
│       ├── match.py             # CVE matching engine
│       ├── recipes.py           # Exploitation recipes & playbooks
│       ├── verify.py            # Post-exploitation verification
│       ├── credattack.py        # Credential attacks (brute force, stuffing)
│       ├── vulns.py             # Vulnerability database & definitions
│       └── plugins_common.py    # Common plugin utilities
│
├── tests/                        # Comprehensive test suite (15 test modules)
│   ├── test_pentest_agent.py   # Agent pipeline tests
│   ├── test_scanner_dork.py    # Discovery engine tests
│   ├── test_exploit.py         # Exploitation tests
│   ├── test_privesc.py         # Privilege escalation tests
│   ├── test_sqli.py            # SQLi detection tests
│   ├── test_authshell.py       # Authentication tests
│   ├── test_fingerprint.py     # Fingerprinting tests
│   ├── test_match.py           # CVE matching tests
│   ├── test_recipes.py         # Recipe tests
│   ├── test_verify.py          # Verification tests
│   ├── test_credattack.py      # Credential attack tests
│   ├── test_vulns.py           # Vulnerability database tests
│   ├── test_learn.py           # Learning module tests
│   ├── test_http_client.py     # HTTP client tests
│   └── test_agent_bridge.py    # Bridge integration tests
│
├── docs/                         # Documentation & research
│   ├── README.md                # Main documentation (this file)
│   ├── TOOLKIT.md               # Complete capability reference
│   ├── CVE-*.md                 # CVE-specific exploitation guides
│   ├── EXPLOIT-*.md             # Detailed exploitation documentation
│   ├── RECIPE-STATUS.md         # Recipe development status
│   ├── ROADMAP.md               # Planned features & enhancements
│   └── superpowers/             # Planning & specification documents
│
├── data/                         # Data files & reference materials
│   ├── scan-*.json              # Shodan scan results (timestamped)
│   ├── scan-*.md                # Scan analysis reports
│   └── domains.txt.example      # Template for asset discovery
│
├── pocs/                         # Proof-of-concept scripts
│   ├── revslider_poc.py         # Revolution Slider vulnerability POC
│   └── eael_quickview_poc.py    # Essential Addons Lightbox POC
│
├── config/                       # Build & test configuration
│   ├── Makefile                 # Build automation
│   ├── Makefile.pentest-agent   # Agent-specific build rules
│   └── pytest.ini               # Pytest configuration
│
├── router/                       # Kubernetes router service (separate component)
│   ├── router.py                # K8s-managed request router
│   ├── k8s-router.yaml          # Kubernetes deployment manifest
│   ├── Dockerfile               # Container image definition
│   └── requirements.txt          # Router-specific dependencies
│
├── requirements.txt              # Python dependencies
├── install.sh                    # Installation script
└── attack_walk.sh                # Manual exploitation walkthrough script
```

## Module Overview

### `src/agents/`
Entry points for the toolkit. `pentest-agent.py` orchestrates a 7-phase pipeline:
1. **RECON** — HTTP fingerprinting, service detection
2. **FINGERPRINT** — WordPress version + plugin detection (live scraping)
3. **SCAN** — Match detected plugins against CVE feeds (Wordfence, NVD)
4. **MATCH** — Rank exploitable CVEs by risk & feasibility
5. **EXPLOIT** — Attempt webshell deployment chains
6. **VERIFY** — Confirm shell persistence & access level
7. **TRACK-B** — Secondary exploitation paths (credential attacks, SQL injection)

### `src/utils/`
Reusable components:
- **`http_client.py`** — Session pooling, header spoofing, proxy support
- **`scanner_dork.py`** — Multi-engine discovery: Shodan, Netlas, Censys (pluggable)
- **`recon.py`** — Live fingerprinting: service detection, SSL certs, header scraping
- **`setup_ragflow.py`** — RAGFlow knowledge-base initialization

### `src/wp/`
Exploitation framework. Each module handles one attack surface:
- **Detection** — `fingerprint.py`, `match.py`, `vulns.py`
- **Exploitation** — `exploit.py`, `privesc.py`, `sqli.py`, `authshell.py`
- **Recipes** — `recipes.py` (templated, composable exploitation chains)
- **Verification** — `verify.py` (post-compromise confirmation)

## Running Tests

```bash
# Install test dependencies
pip install -r requirements.txt pytest pytest-cov

# Run all tests
pytest tests/ -v

# Run specific module tests
pytest tests/test_exploit.py -v

# Generate coverage report
pytest tests/ --cov=src/wp --cov-report=html
```

## Development Workflow

1. **Add a new vulnerability recipe** → edit `src/wp/recipes.py`
2. **Fix a detection bug** → update `src/wp/fingerprint.py` or `src/wp/match.py`, add test in `tests/test_fingerprint.py`
3. **Add a new scanner backend** → extend `src/utils/scanner_dork.py` with new engine class
4. **New exploit technique** → add method to `src/wp/exploit.py`, test in `tests/test_exploit.py`

All changes should include corresponding test cases in `tests/`.
