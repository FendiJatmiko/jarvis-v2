# Shodan Setup Guide

This toolkit primarily uses **Shodan** for internet-wide discovery. Here's how to set it up:

## What is Shodan?

Shodan is a search engine for the internet — it indexes connected devices and services by their fingerprints. The scanner uses Shodan dorks (queries) to find exposed WordPress sites.

📖 Learn more: https://www.shodan.io/

## Step 1: Get a Shodan API Key

### Option A: Free Account (Limited)
```bash
1. Go to https://www.shodan.io
2. Click "Register" and create an account
3. Go to Account → API (https://account.shodan.io/settings/shodan/apps)
4. Copy your API Key
5. Free accounts get limited queries (mostly for --test validation)
```

### Option B: Paid Account (Recommended)
```bash
For scanning your assets, you'll need:
- Paid Shodan membership ($49/month basic plan)
- Query credits (varies, but basic plan includes daily allowance)
- Use --country to scope searches and save credits

Learn more: https://www.shodan.io/billing
```

## Step 2: Set the Environment Variable

### Linux/Mac (Temporary - this session only)
```bash
export SHODAN_API_KEY=sk_your_actual_api_key_here
```

### Linux/Mac (Permanent - add to ~/.bashrc or ~/.zshrc)
```bash
# Edit your shell config file
nano ~/.zshrc
# (or nano ~/.bashrc for bash)

# Add this line at the end:
export SHODAN_API_KEY=sk_your_actual_api_key_here

# Save and reload:
source ~/.zshrc
```

### Windows (PowerShell)
```powershell
$env:SHODAN_API_KEY = "sk_your_actual_api_key_here"
```

### Windows (Command Prompt)
```cmd
set SHODAN_API_KEY=sk_your_actual_api_key_here
```

## Step 3: Verify Your Setup

```bash
# Test that your key is set correctly
echo $SHODAN_API_KEY

# Run the scanner in test mode (free, no credits used)
python3 -m src.utils.scanner_dork --engine shodan --test
```

**Expected output:**
```
[*] Testing Shodan credentials...
[+] Valid API key
[+] Account type: basic
[+] Query credits remaining: 123
```

## Step 4: Run Discovery

### Basic Scan (Finds WordPress sites)
```bash
python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt
```

**What it does:**
1. Reads your domain list from `domains.txt`
2. Queries Shodan for exposed WordPress sites
3. Saves results to `data/scan-<timestamp>.md` and `.json`
4. Flags any of YOUR domains that appear in exposed results

### Country-Scoped Scan (Saves Credits)
```bash
python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt --country ID
```

Options:
- `--country ID` — Indonesia
- `--country US` — United States
- `--country GB` — United Kingdom
- etc. (use 2-letter country codes)

**Saves 50-80% of query credits by scoping geographically.**

### Network Scan (Your IP Range)
```bash
python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt --net 203.0.113.0/24
```

## Understanding Query Credits

- **Free account**: Limited queries, mainly for testing
- **Paid account**: 100 queries/month (basic) or more
- **Each dork query uses 1 credit**
- **Number of dorks**: 8-10 depending on categories selected

**Example:**
- WordPress hosts category: ~2 dorks = 2 credits
- Full scan (all categories): ~20 credits per run
- With `--country`: 1-2 credits per category

## Troubleshooting

### "Invalid API key"
```bash
# Check your key is set:
echo $SHODAN_API_KEY

# If empty, run:
export SHODAN_API_KEY=sk_your_key_here

# If it still fails, check:
# 1. You copied the full key (starts with sk_)
# 2. No extra spaces before/after
# 3. Key is from your actual Shodan account
```

### "Not enough credits"
```bash
# Check remaining credits:
python3 -m src.utils.scanner_dork --engine shodan --test

# Options to save credits:
# 1. Use --country to scope geographically
# 2. Use --net to scope to your network only
# 3. Wait for monthly credit reset (if on paid plan)
# 4. Upgrade your Shodan plan
```

### "No results found"
```bash
# This is normal if:
# 1. You have no exposed WordPress sites (good!)
# 2. All your sites are properly firewalled
# 3. Shodan hasn't indexed your infrastructure yet

# To verify Shodan indexed your domains, manually search:
# Go to https://www.shodan.io/search?query=example.com
```

## Alternative Engines (Optional)

This toolkit supports other discovery engines, but **Shodan is recommended**:

| Engine | Setup | Cost | Coverage |
|--------|-------|------|----------|
| **Shodan** | API key (free/paid) | Free tier or $49+/mo | Largest database, best for WordPress |
| Netlas | Free account | ~1500 queries/month free | Good alternative |
| Censys | Free account | Limited | Academic focus |
| Google Custom Search | API key | $100/month | Limited web coverage |

**For other engines:**
```bash
export NETLAS_API_KEY=your_key_here
export CENSYS_PAT=your_pat_here
export GOOGLE_API_KEY=your_key_here
export GOOGLE_CX=your_cx_here

python3 -m src.utils.scanner_dork --engine netlas --mine domains.txt
```

## Complete Workflow

```bash
# 1. Set up Shodan key (once)
export SHODAN_API_KEY=sk_your_key_here

# 2. Test credentials
python3 -m src.utils.scanner_dork --engine shodan --test

# 3. Create your domain list
cp data/domains.txt.example domains.txt
# Edit domains.txt with your assets

# 4. Run discovery scan
python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt --country ID

# 5. Review results
cat data/scan-*.md | grep "YOUR MATCH"

# 6. Deep inspect flagged sites
python3 -m src.agents.pentest_agent https://flagged-site.tld --mode plan

# 7. Full assessment (on approved targets only)
python3 -m src.agents.pentest_agent https://target.tld --no-cleanup
```

## Quick Reference

```bash
# Display your current API key (verify it's set)
echo $SHODAN_API_KEY

# Test Shodan connectivity (free, no credits)
python3 -m src.utils.scanner_dork --engine shodan --test

# Run scanner with Shodan
python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt

# Scope to save credits
python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt --country ID --net 10.0.0.0/8

# Check help
python3 -m src.utils.scanner_dork --help
```

## Security Notes

⚠️ **Never commit your API key to git!**

```bash
# If you accidentally committed your key:
1. Regenerate it at https://account.shodan.io/settings/shodan/apps
2. Update your environment variable
3. Consider using git-secrets to prevent this
```

## Need Help?

- **Shodan Documentation**: https://developer.shodan.io/
- **Scanner Options**: `python3 -m src.utils.scanner_dork --help`
- **Pricing Calculator**: https://www.shodan.io/billing

---

**TL;DR:**
```bash
1. Get API key: https://www.shodan.io → Register → Account → API
2. Set it: export SHODAN_API_KEY=sk_your_key_here
3. Test it: python3 -m src.utils.scanner_dork --engine shodan --test
4. Use it: python3 -m src.utils.scanner_dork --engine shodan --mine domains.txt
```
