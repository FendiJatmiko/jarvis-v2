#!/usr/bin/env python3
"""
dork-check.py — self-assessment: is any of MY site discoverable/injected via Google dorks?

Runs a curated library of Google dork queries against a list of domains YOU own,
plus a direct cloaking/injection self-probe that doesn't need Google at all.

Three engines (used together):
  1. Google Custom Search JSON API  — real automated results (needs API key + CX)
  2. Clickable-URL report           — always works, open the dorks yourself
  3. Direct self-probe              — fetch each site as Googlebot vs normal, diff
                                       for gambling/spam keywords (catches cloaking)

Usage:
  # 1. Put your domains (one per line) in domains.txt   (bare hostnames, no scheme)
  # 2a. With Google Custom Search API (recommended):
  export GOOGLE_API_KEY=...            # https://developers.google.com/custom-search/v1/overview
  export GOOGLE_CX=...                 # https://programmablesearchengine.google.com  (set to "search entire web")
  python3 dork-check.py --domains domains.txt

  # 2b. No API key — generate clickable URLs + run the self-probe only:
  python3 dork-check.py --domains domains.txt --no-api

  # Just the direct injection self-probe (fastest, no Google at all):
  python3 dork-check.py --domains domains.txt --probe-only

Output:
  dork-report-<timestamp>.md   (human-readable, hits highlighted)
  dork-report-<timestamp>.json (machine-readable)
"""
import argparse
import json
import os
import sys
import time
import urllib.parse
from datetime import datetime, timezone

import requests

# ---------------------------------------------------------------------------
# Dork library — {domain} is substituted per site.
# Curated for the gambling-SEO-injection threat, plus generic exposure.
# ---------------------------------------------------------------------------

# Multilingual gambling/spam keywords seen in real ID/KR/JP campaigns.
SPAM_KEYWORDS = [
    "judi", "slot", "togel", "bandar", "poker", "casino", "sbobet", "gacor",
    "situs", "deposit", "카지노", "슬롯", "바카라", "賭博", "オンラインカジノ",
    "bet", "gambling", "jackpot", "maxwin",
]

DORKS = {
    "injection_gambling": [
        # Is my domain already indexed with gambling spam? (the smoking gun)
        'site:{domain} (judi OR slot OR togel OR bandar OR casino OR sbobet OR gacor)',
        'site:{domain} (카지노 OR 슬롯 OR 바카라)',
        'site:{domain} (賭博 OR オンラインカジノ)',
        'site:{domain} intitle:(slot OR togel OR casino OR judi)',
        'site:{domain} inurl:(slot OR togel OR judi OR casino OR bet)',
    ],
    "exposed_sensitive_files": [
        'site:{domain} ext:sql OR ext:bak OR ext:old OR ext:swp',
        'site:{domain} inurl:wp-config',
        'site:{domain} intitle:"index of" wp-content',
        'site:{domain} intitle:"index of" (backup OR uploads OR db)',
        'site:{domain} ext:env OR ext:log OR ext:ini',
        'site:{domain} inurl:.git',
    ],
    "login_admin_surfaces": [
        'site:{domain} inurl:wp-login.php',
        'site:{domain} inurl:wp-admin',
        'site:{domain} inurl:xmlrpc.php',
        'site:{domain} intitle:"phpMyAdmin"',
        'site:{domain} inurl:(login OR admin OR dashboard)',
    ],
    "info_disclosure": [
        'site:{domain} intitle:"phpinfo()"',
        'site:{domain} inurl:readme.html',      # leaks WP version
        'site:{domain} "sql syntax near" OR "mysql_fetch" OR "Warning: mysql"',
        'site:{domain} intext:"Index of /" "Parent Directory"',
    ],
}


def load_domains(path: str) -> list:
    with open(path) as f:
        out = []
        for line in f:
            d = line.strip()
            if not d or d.startswith("#"):
                continue
            # normalize: strip scheme / trailing slash / path
            d = d.replace("https://", "").replace("http://", "").split("/")[0]
            out.append(d)
    return out


def google_url(query: str) -> str:
    return "https://www.google.com/search?q=" + urllib.parse.quote(query)


def run_custom_search(query: str, api_key: str, cx: str) -> dict:
    """Query Google Custom Search JSON API. Returns {count, items:[{title,link}], error}."""
    try:
        r = requests.get(
            "https://www.googleapis.com/customsearch/v1",
            params={"key": api_key, "cx": cx, "q": query, "num": 10},
            timeout=30,
        )
        if r.status_code == 429:
            return {"count": None, "items": [], "error": "rate_limited (daily quota hit)"}
        r.raise_for_status()
        data = r.json()
        total = int(data.get("searchInformation", {}).get("totalResults", "0"))
        items = [{"title": i.get("title"), "link": i.get("link")}
                 for i in data.get("items", [])]
        return {"count": total, "items": items, "error": None}
    except Exception as e:
        return {"count": None, "items": [], "error": f"{e.__class__.__name__}: {e}"}


def self_probe(domain: str) -> dict:
    """Fetch site as Googlebot vs normal browser; flag gambling keywords + cloaking."""
    result = {"domain": domain, "googlebot_hits": [], "normal_hits": [],
              "cloaking": False, "error": None}
    headers_bot = {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; "
                                 "+http://www.google.com/bot.html)"}
    headers_usr = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                 "AppleWebKit/537.36 (KHTML, like Gecko) "
                                 "Chrome/120.0 Safari/537.36"}
    try:
        for scheme in ("https://", "http://"):
            try:
                bot = requests.get(scheme + domain, headers=headers_bot,
                                   timeout=15, allow_redirects=True)
                usr = requests.get(scheme + domain, headers=headers_usr,
                                   timeout=15, allow_redirects=True)
                break
            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.ConnectionError:
                continue
        else:
            result["error"] = "unreachable"
            return result

        bot_l, usr_l = bot.text.lower(), usr.text.lower()
        result["googlebot_hits"] = [k for k in SPAM_KEYWORDS if k.lower() in bot_l]
        result["normal_hits"] = [k for k in SPAM_KEYWORDS if k.lower() in usr_l]
        # cloaking = gambling keywords shown to Googlebot but NOT to normal users
        result["cloaking"] = bool(set(result["googlebot_hits"])
                                  - set(result["normal_hits"]))
    except Exception as e:
        result["error"] = f"{e.__class__.__name__}: {e}"
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="Self-assess Google-dork exposure of your own domains.")
    ap.add_argument("--domains", required=True, help="file with one domain per line")
    ap.add_argument("--no-api", action="store_true", help="skip Custom Search API; URLs + probe only")
    ap.add_argument("--probe-only", action="store_true", help="only run the direct injection self-probe")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between API queries")
    args = ap.parse_args()

    domains = load_domains(args.domains)
    if not domains:
        sys.exit("No domains found in file.")

    api_key = os.environ.get("GOOGLE_API_KEY")
    cx = os.environ.get("GOOGLE_CX")
    use_api = bool(api_key and cx) and not args.no_api and not args.probe_only

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    report = {"generated": ts, "domains": domains, "dork_results": [], "probe_results": []}

    print(f"[*] {len(domains)} domain(s) loaded.")
    print(f"[*] Custom Search API: {'ENABLED' if use_api else 'disabled (URL + probe mode)'}")

    # --- Direct self-probe (always) ---
    print("\n[*] Running direct injection self-probe (Googlebot vs normal UA)...")
    for d in domains:
        pr = self_probe(d)
        report["probe_results"].append(pr)
        if pr["error"]:
            print(f"    {d}: [!] {pr['error']}")
        elif pr["cloaking"]:
            print(f"    {d}: [!!!] CLOAKING DETECTED — gambling keywords served to "
                  f"Googlebot only: {pr['googlebot_hits']}")
        elif pr["googlebot_hits"]:
            print(f"    {d}: [!] gambling keywords present: {pr['googlebot_hits']}")
        else:
            print(f"    {d}: clean")

    # --- Dork queries ---
    if not args.probe_only:
        print("\n[*] Running dork library...")
        for d in domains:
            for category, templates in DORKS.items():
                for tmpl in templates:
                    q = tmpl.format(domain=d)
                    entry = {"domain": d, "category": category, "query": q,
                             "url": google_url(q)}
                    if use_api:
                        res = run_custom_search(q, api_key, cx)
                        entry.update(res)
                        flag = ""
                        if res["error"]:
                            flag = f"[err: {res['error']}]"
                        elif res["count"]:
                            flag = f"[!!! {res['count']} HIT(S)]"
                        else:
                            flag = "[clean]"
                        print(f"    {d} / {category}: {flag}")
                        time.sleep(args.delay)
                    report["dork_results"].append(entry)

    # --- Write reports ---
    json_path = f"dork-report-{ts}.json"
    md_path = f"dork-report-{ts}.md"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with open(md_path, "w") as f:
        f.write(f"# Dork self-assessment — {ts}\n\n")
        f.write("## Direct injection self-probe\n\n")
        for pr in report["probe_results"]:
            if pr["error"]:
                f.write(f"- **{pr['domain']}** — error: {pr['error']}\n")
            elif pr["cloaking"]:
                f.write(f"- 🚨 **{pr['domain']}** — **CLOAKING**: served to Googlebot only: "
                        f"`{', '.join(pr['googlebot_hits'])}`\n")
            elif pr["googlebot_hits"]:
                f.write(f"- ⚠️ **{pr['domain']}** — gambling keywords present: "
                        f"`{', '.join(pr['googlebot_hits'])}`\n")
            else:
                f.write(f"- ✅ **{pr['domain']}** — clean\n")

        f.write("\n## Dork queries\n\n")
        if use_api:
            hits = [e for e in report["dork_results"] if e.get("count")]
            f.write(f"**{len(hits)} query(ies) returned results** "
                    f"out of {len(report['dork_results'])} run.\n\n")
            for e in hits:
                f.write(f"### 🚨 {e['domain']} — {e['category']} ({e['count']} results)\n")
                f.write(f"`{e['query']}`\n\n")
                for it in e["items"]:
                    f.write(f"- [{it['title']}]({it['link']})\n")
                f.write("\n")
        else:
            f.write("_API disabled — open these URLs manually to check each dork._\n\n")
            cur = None
            for e in report["dork_results"]:
                if e["domain"] != cur:
                    cur = e["domain"]
                    f.write(f"\n### {cur}\n\n")
                f.write(f"- {e['category']}: [{e['query']}]({e['url']})\n")

    print(f"\n[*] Reports written:\n    {md_path}\n    {json_path}")


if __name__ == "__main__":
    main()
