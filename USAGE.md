# Jarvis v2 — Usage Guide

After reorganization, all source code is now under `src/`. Here's how to run the toolkit:

## 1. Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 -c "from src.agents import pentest_agent; print(f'✓ Ready: v{pentest_agent.__version__}')"
```

## 2. Internet-Wide Discovery (Scanner)

Find exposed WordPress sites using Shodan, Netlas, or Censys:

```bash
# Setup: Create your domains file
cp data/domains.txt.example domains.txt
# Edit domains.txt with your assets (one per line)

# Export your API key
export SHODAN_API_KEY=your_api_key_here

# Test your Shodan credentials (free, no credits used)
python3 -m src.utils.scanner_dork --engine shodan --test

# Scan and flag your own sites
python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt

# Scope to a country to save credits
python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt --country ID

# Scan your own network (CIDR)
python3 -m src.utils.scanner_dork --engine netlas --mine domains.txt --net 203.0.113.0/24

# Output: scan-<timestamp>.md / .json
```

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
# Discovery engines
export SHODAN_API_KEY=sk_...          # Required for Shodan
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
