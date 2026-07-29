# CVE Scanner — Hardcoded Vulnerability Detection

Scan your infrastructure from an **attacker's perspective** using hardcoded signatures of 9 critical WordPress plugin vulnerabilities commonly exploited in compromised farms.

## Concept

Instead of generic dorks, the scanner now includes **specific, battle-tested signatures** for vulnerabilities that were likely used to compromise your farm. It runs these automatically with every scan.

## Quick Start

```bash
# Scan your infrastructure for all 9 vulnerable plugins
python3 scanner_dork.py --mine domains.txt

# Same, but quiet (no line-by-line output)
python3 scanner_dork.py --mine domains.txt --quiet

# Scope to your country/region
python3 scanner_dork.py --mine domains.txt --country ID

# Scope to your public networks only
python3 scanner_dork.py --mine domains.txt --net 203.0.113.0/24,198.51.100.0/24
```

## The 9 Hardcoded CVEs

Each CVE includes **3 detection signatures**, giving you 27 total Shodan queries:

| CVE | Vulnerability | Plugin/Product | Type |
|-----|---------------|----------------|------|
| CVE-2020-24186 | wpDiscuz file upload | wpDiscuz 7.0-7.0.4 | RCE |
| CVE-2023-32243 | Essential Addons auth bypass | Essential Addons for Elementor | Auth Bypass |
| CVE-2024-25600 | Bricks REST API | Bricks Builder Theme | RCE |
| CVE-2025-6389 | Sneeit AJAX injection | Sneeit Framework | RCE |
| CVE-2025-7384 | Contact Form 7 DB | Database for CF7/WPForms | RCE |
| CVE-2026-3844 | Breeze Cache upload | Breeze Cache Plugin | RCE |
| CVE-2026-1357 | WPvivid path traversal | WPvivid Backup & Migration | RCE |
| CVE-2026-63030 | WordPress REST batch (wp2shell) | WordPress Core 6.9-7.0 | RCE |
| CVE-2026-2580 | WP Maps SQLi | WP Maps Store Locator | SQLi |

## What It Does

For each scan:

1. **Runs all 9 CVE fingerprints** (27 signatures total)
2. **Searches the internet** via Shodan for exposed instances
3. **Cross-references your infrastructure** against hits
4. **Flags any matches** to your domains/networks
5. **Reports findings** in `scan-<timestamp>.md`

## Output

If your domains appear in the report:

```
🚨 YOUR HOST SURFACED
- my-site.example.com (owned: example.com) — [CVE-2025-7384]
```

This means: **Your infrastructure is vulnerable to CVE-2025-7384 and exposed on the internet.** Attackers scanning for this fingerprint would find you.

## How It Works

Each CVE has multiple detection signatures because vulnerable software leaves different "fingerprints" in HTTP responses:

**Example: CVE-2025-7384 (Contact Form 7 Database)**

```
1. http.html:"database-db-manager-for-contact-form-7"
2. http.html:"get_lead_detail" http.component:"WordPress"
3. http.html:"Contact Form 7" http.html:"form submission"
```

The scanner searches for ANY of these patterns, so even if the plugin hides its name, we might catch it via function names or capabilities.

## Performance

- **Shodan credits**: ~27 queries per run (one per signature)
- **Speed**: Depends on Shodan tier and query results
- **Quiet mode**: Faster visual feedback when you don't need line-by-line output
- **Country filter**: Saves credits by narrowing scope

## Next Steps After Finding Matches

If your domains appear in results:

1. **Patch immediately** — Update the vulnerable plugin to the patched version
2. **Check logs** — See if you were already exploited (search for the CVE-related patterns in logs)
3. **Remediate** — If exploited, hunt for webshells and backdoors
4. **Monitor** — Re-scan weekly after patches to confirm they're gone

## API Key Setup

Requires a **paid Shodan membership** with query credits:

```bash
export SHODAN_API_KEY=xxx...
python3 scanner_dork.py --test   # Validate your key + see credits
```

## Implementation Details

- Hardcoded signatures = no API calls during scan (faster, no NVD dependency)
- Runs alongside standard dorks (WordPress, databases, admin panels, etc.)
- Use `--query` to override and run a custom single query instead
- Use `--only` to filter which dork categories to run (CVEs still run)
