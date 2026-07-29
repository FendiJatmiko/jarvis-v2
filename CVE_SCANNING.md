# CVE-Based Scanner

Scan your infrastructure from an **attacker's perspective** by hunting for instances of software vulnerable to specific CVEs.

## Concept

Instead of using predefined dorks, this mode:
1. Takes a list of CVE IDs from NVD (National Vulnerability Database)
2. Extracts the **affected products and versions** for each CVE
3. Builds Shodan fingerprint queries to find those vulnerable instances **exposed on the internet**
4. Cross-references results against your **own domains/networks** (via `--mine`)

This mirrors the attacker's discovery workflow: "find all instances of vulnerable software XYZ" rather than "find WordPress".

## Usage

### Basic: Hunt for instances of vulnerable CVEs on your infrastructure

```bash
python3 scanner_dork.py --mine domains.txt --vuln cves.txt
```

### Quiet mode (suppresses live output)

```bash
python3 scanner_dork.py --mine domains.txt --vuln cves.txt --quiet
```

### Scope to your public networks

```bash
python3 scanner_dork.py --mine domains.txt --vuln cves.txt --net 203.0.113.0/24
```

### Scope to a country (saves API credits)

```bash
python3 scanner_dork.py --mine domains.txt --vuln cves.txt --country ID
```

## CVE File Format

One CVE ID per line, comments with `#`:

```
# Critical WordPress plugin vulns we were exploited through
CVE-2023-46805
CVE-2023-27997

# Ivanti auth bypass — check for exposed instances
CVE-2024-21887
```

## What It Does

For each CVE:

1. **Fetches from NVD API** — retrieves affected products, versions, and descriptions
2. **Extracts fingerprints** — products like WordPress plugins, web servers, databases, etc.
3. **Builds Shodan queries** — e.g., `http.html:"plugin-name" http.component:"WordPress"`
4. **Searches internet-wide** — finds exposed instances
5. **Cross-references your assets** — flags if any of YOUR domains appear in results

## Output

Same as regular scans:
- `scan-<timestamp>.md` — your matches highlighted, then raw harvested pile
- `scan-<timestamp>.json` — machine-readable results including CVE-based hits

## Example Workflow

You suspect a WordPress plugin backdoor from the slot gaming farm attack:

```bash
# 1. Create a file of CVEs you're concerned about
echo "CVE-2023-46805
CVE-2023-27997
CVE-2024-21887" > suspect_cves.txt

# 2. Scan your own infrastructure + networks
python3 scanner_dork.py \
  --mine my_domains.txt \
  --vuln suspect_cves.txt \
  --country ID \  # your region
  --quiet

# 3. Check results
cat scan-*.md
```

If your infrastructure appears in "YOUR HOSTS SURFACED", you know:
- You're vulnerable to that CVE
- It's exposed to the internet
- Attackers scanning for that fingerprint would find you

## Performance Tips

- **NVD API**: Public, free, but has rate limits (~1 call/second). The tool sleeps 0.1s between requests by default.
- **Query credits**: Each Shodan query uses credits. CVE mode may generate many queries (depends on affected products).
- **Estimate**: If you provide 10 CVEs and each has 2-3 affected products, expect 20-30 queries.
- **Use `--pages 1`** if you just want to see if vulnerable versions exist (doesn't use as many credits).

## Troubleshooting

**CVEs not generating queries?**
- The CVE may have no affected products in NVD's database
- Try `python3 -c "from scanner_dork import fetch_cve_info; print(fetch_cve_info('CVE-XXXX-XXXX'))"` to debug

**Shodan 403 errors?**
- You're out of query credits. Check with `--test`.
- CVE mode needs a paid Shodan membership.

**NVD API slow?**
- This is normal. The tool throttles to 1 call/second to be polite.
- Increase `--delay` if you're hitting rate limits.
