# Jarvis v2 — Usage Guide

After reorganization, all source code is now under `src/`. Here's how to run the toolkit:

> ⚠️ **IMPORTANT**: This toolkit uses **Shodan** for internet-wide discovery. You'll need a Shodan API key to scan for exposed sites.
> - **Free tier**: Testing & validation only
> - **Paid tier**: $49/month basic plan for production scanning
> - **Setup**: See [SHODAN_SETUP.md](SHODAN_SETUP.md) for detailed instructions

## 1. Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 -c "from src.agents import pentest_agent; print(f'✓ Ready: v{pentest_agent.__version__}')"
```

## 2. Internet-Wide Discovery (Scanner)

🔑 **REQUIRES SHODAN API KEY** — See [SHODAN_SETUP.md](SHODAN_SETUP.md) for detailed setup instructions

Find exposed WordPress sites using **Shodan** (recommended) or alternatives:

```bash
# STEP 1: Get Shodan API key (required)
# Go to https://www.shodan.io → Register → Account → API
# Copy your key (looks like: sk_...)

# STEP 2: Set environment variable
export SHODAN_API_KEY=sk_your_actual_key_here

# STEP 3: Test your Shodan credentials (free, no credits used)
python3 -m src.utils.scanner_dork --engine shodan --test

# STEP 4: Create your domains file
cp data/domains.txt.example domains.txt
# Edit domains.txt with your assets (one per line)

# STEP 5: Run discovery scan
python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt

# Optional: Scope to a country to save Shodan credits (50-80% savings)
python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt --country ID

# Optional: Scan your own network (CIDR) only
python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt --net 203.0.113.0/24

# Output: scan-<timestamp>.md / .json
```

**Why Shodan?**
- Largest database of exposed services internet-wide
- Most accurate for WordPress detection
- Free tier for testing (--test only)
- Paid plans from $49/month for production scanning

**Alternative engines** (optional, see [SHODAN_SETUP.md](SHODAN_SETUP.md)):
- Netlas: ~1500 queries/month free
- Censys: Limited, academic focus
- Google Custom Search: $100/month

## 3. Per-Site Assessment (Pentest Agent)

Deep inspection & exploitation of one WordPress site:

```bash
# Detection only (no exploitation)
python3 -m src.agents.pentest_agent https://target.tld --mode plan

# Full assessment (detection + exploitation attempt)
python3 -m src.agents.pentest_agent https://target.tld

# Quiet mode (less verbose)
python3 -m src.agents.pentest_agent https://target.tld --quiet

# Deep scan (RAGFlow checks for plugins missing from feeds)
python3 -m src.agents.pentest_agent https://target.tld --deep

# Confirm each action before executing
python3 -m src.agents.pentest_agent https://target.tld --mode safe

# Keep the planted webshell (don't cleanup)
python3 -m src.agents.pentest_agent https://target.tld --no-cleanup
```

### Pentest Agent Phases

The agent runs 7 phases:

1. **RECON** — HTTP fingerprinting, service detection
2. **FINGERPRINT** — WordPress version + plugin detection
3. **SCAN** — Match plugins against CVE feeds (Wordfence, NVD)
4. **MATCH** — Rank exploitable CVEs by risk
5. **EXPLOIT** — Attempt webshell deployment
6. **VERIFY** — Confirm shell persistence & access level
7. **TRACK-B** — Secondary paths (credentials, SQL injection)

## 4. Manual Exploitation Walkthrough

Understand one exposure step-by-step:

```bash
# Manual walkthrough with verbose output
./attack_walk.sh https://clone.tld --loud -V

# With database / cache checks
./attack_walk.sh https://clone.tld --db --loud -V
```

## 5. Chaining Discovery → Exploitation

Typical workflow:

```bash
# Step 1: Discover exposed sites
python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt --country ID > scan.txt

# Step 2: Review scan results (data/scan-*.md)
cat data/scan-*.md | grep "YOUR MATCH"

# Step 3: Deep inspect flagged sites
python3 -m src.agents.pentest_agent https://flagged-1.tld --mode plan
python3 -m src.agents.pentest_agent https://flagged-2.tld --mode plan

# Step 4: Run full assessment (on approved targets only)
python3 -m src.agents.pentest_agent https://target.tld --no-cleanup
```

## 6. Environment Variables

```bash
# REQUIRED for internet-wide discovery:
export SHODAN_API_KEY=sk_...          # ⭐ Required for scanner (get from https://shodan.io)

# Optional alternative discovery engines:
export NETLAS_API_KEY=...             # Optional for Netlas
export CENSYS_PAT=...                 # Optional for Censys
export GOOGLE_API_KEY=...             # Optional for Google
export GOOGLE_CX=...                  # Optional (Custom Search CX)

# Pentest agent
export WORDFENCE_API_KEY=...          # For --deep scanning (free key available)
export OLLAMA_URL=...                 # LLM for analysis (optional)
export OLLAMA_KEY=...
export RAGFLOW_URL=...                # RAGFlow knowledge base
export RAGFLOW_KEY=...
export RAGFLOW_CHAT=...
```

## 7. Running Tests

```bash
# All tests
python3 -m pytest tests/ -v

# Specific module
python3 -m pytest tests/test_exploit.py -v

# With coverage
python3 -m pytest tests/ --cov=src/wp --cov-report=html
```

## 8. Project Structure (After Reorganization)

```
src/
├── agents/           # Main agents (pentest-agent, pentest-ai, bridge)
├── utils/            # Utilities (scanner, http client, learning)
└── wp/               # WordPress exploitation framework

tests/                # 248 test modules
docs/                 # Documentation
data/                 # Sample data, scan results
pocs/                 # POC scripts
config/               # Build configs (Makefile, pytest.ini)
```

## 9. Common Issues & Fixes

### "ModuleNotFoundError: No module named 'src'"
```bash
# Make sure you're running from project root:
cd /path/to/jarvis-v2
python3 -m src.agents.pentest_agent https://target.tld
```

### "agent-path not found"
```bash
# Scanner looks for pentest_agent.py in src/agents/
# Specify it explicitly if needed:
python3 -m src.utils.scanner_dork --agent-path ./src/agents/pentest_agent.py --mine domains.txt
```

### "SHODAN_API_KEY not set" or "Invalid API key"
```bash
# This tool REQUIRES Shodan API key for discovery
# See SHODAN_SETUP.md for complete setup instructions

# Quick check:
echo $SHODAN_API_KEY

# If empty, set it:
export SHODAN_API_KEY=sk_your_actual_key_here

# Get free key from https://www.shodan.io → Register → Account → API
```

### "Not enough credits"
```bash
# Shodan paid plans have monthly query limits
# Save credits by scoping geographically or by network:
python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt --country ID --net 10.0.0.0/8
# Saves 50-80% of query credits
```

### "WORDFENCE_API_KEY not set"
```bash
# Optional for SCAN phase; without it, runs feed-less
export WORDFENCE_API_KEY=...
# Or get a free key at wordfence.com
```

## 10. Quick Reference

| Task | Command |
|------|---------|
| Find exposed sites | `python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt` |
| Inspect one site | `python3 -m src.agents.pentest_agent https://target.tld --mode plan` |
| Exploit one site | `python3 -m src.agents.pentest_agent https://target.tld` |
| Run tests | `python3 -m pytest tests/ -v` |
| View help | `python3 -m src.agents.pentest_agent --help` |
| View scanner help | `python3 -m src.utils.scanner_dork --help` |

## Important Notes

⚠️ **Authorized use only** — Run against your own / your clients' assets, or a clone.

- Scanner sees *exposure* (Shodan's index); pentest-agent sees *deep truth* (live CVEs)
- A scanner hit is a *lead*, not a verdict
- Always test on a clone first if possible
- Use `--mode safe` to confirm each action
- Wordfence API key is optional (runs feed-less without it)

---

**Documentation**: See `docs/TOOLKIT.md` for complete reference.
**Contribute**: See `docs/ROADMAP.md` for planned features.
