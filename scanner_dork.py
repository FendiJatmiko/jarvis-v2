#!/usr/bin/env python3
"""
scanner_dork.py — attacker's-eye view: run UNSCOPED internet-wide dork/fingerprint
queries, harvest every host that surfaces, then flag any of YOUR (or your clients')
domains that landed in the "exposed / vulnerable" pile.

This replicates the attacker DISCOVERY step: they don't target you by name — they
scan the whole internet for a vulnerable fingerprint and you either show up or you
don't. This tool lets you see what they'd see.

TWO ENGINES:

  --engine shodan   (recommended, what attackers actually use for whole-internet)
      Purpose-built internet-wide scanner, indexed by fingerprint, proper API.
      Needs a Shodan API key.  Note: the search API requires a paid Shodan
      membership + query credits; a free key can only call --test / api-info.
      Setup:  shodan.io -> register -> Account -> copy API key
              export SHODAN_API_KEY=...

  --engine google   (supplementary; Google restricts internet-wide PSE by design)
      Google Custom Search JSON API with a CX set to "search entire web".
      Setup:  export GOOGLE_API_KEY=...   export GOOGLE_CX=...

Usage:
  # Validate your Shodan key + see plan / remaining query credits (free, no credits used):
  python3 scanner_dork.py --engine shodan --test

  # Harvest internet-wide WordPress/exposed hosts and flag your own domains:
  python3 scanner_dork.py --engine shodan --mine domains.txt

  # Scope the harvest to a country to save credits + raise the odds your sites appear:
  python3 scanner_dork.py --engine shodan --mine domains.txt --country ID

  # Discover YOUR OWN estate via your TLS cert (great for a subdomain farm):
  python3 scanner_dork.py --engine shodan --mine domains.txt --cn nzmweb.com

  # Google engine (needs entire-web CX):
  python3 scanner_dork.py --engine google --mine domains.txt

Output:
  scan-<timestamp>.md   — YOUR matches highlighted first, then the raw harvested pile
  scan-<timestamp>.json — full machine-readable results
"""
import argparse
import json
import os
import sys
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone

import requests

# ---------------------------------------------------------------------------
# Shodan queries — Shodan filter syntax (NOT Google dork syntax).
# These surface exposed/vulnerable hosts internet-wide, as an attacker harvests.
# {country} is filled in when --country is passed, else removed.
# ---------------------------------------------------------------------------
SHODAN_DORKS = {
    "wordpress_hosts": [
        'http.component:"WordPress" {country}',
        'http.html:"wp-content/plugins" {country}',
    ],
    "exposed_listings": [
        'http.title:"Index of /" http.html:"wp-content" {country}',
        'http.title:"Index of /" http.html:"backup" {country}',
    ],
    "login_surfaces": [
        'http.html:"xmlrpc.php" http.component:"WordPress" {country}',
        'http.title:"phpMyAdmin" {country}',
    ],
    "injected_gambling": [
        'http.title:"slot" http.html:"wp-content" {country}',
        'http.html:"judi" http.component:"WordPress" {country}',
    ],
}

# ---------------------------------------------------------------------------
# Censys Platform queries — Censys Query Language (CenQL), internet-wide.
# {country} -> ` and host.location.country_code="XX"` when --country given.
# ---------------------------------------------------------------------------
CENSYS_DORKS = {
    "wordpress_hosts": [
        'host.services.software.product="WordPress"{country}',
    ],
    "exposed_listings": [
        'host.services.http.response.html_title="Index of /"{country}',
    ],
    "login_surfaces": [
        'host.services.http.response.body:"xmlrpc.php"{country}',
        'host.services.http.response.html_title="phpMyAdmin"{country}',
    ],
    "injected_gambling": [
        'host.services.http.response.html_title:"slot"{country}',
        'host.services.http.response.body:"judi"{country}',
    ],
}

# ---------------------------------------------------------------------------
# Netlas queries — Netlas query language, internet-wide, FREE-TIER SEARCH.
# {country} -> ` AND geo.country:XX` when --country given.
# ---------------------------------------------------------------------------
NETLAS_DORKS = {
    "wordpress_hosts": [
        'http.body:"wp-content"{country}',
    ],
    "joomla_hosts": [
        'http.body:"/media/system/js/"{country}',
        'http.title:"Joomla"{country}',
    ],
    "exposed_listings": [
        'http.title:"Index of /"{country}',
    ],
    "login_surfaces": [
        'http.body:"xmlrpc.php"{country}',
    ],
    "injected_gambling": [
        'http.title:"slot"{country}',
        'http.body:"judi"{country}',
    ],
}

# ---------------------------------------------------------------------------
# Google unscoped dorks (NO site:). Supplementary engine.
# ---------------------------------------------------------------------------
GOOGLE_DORKS = {
    "injected_gambling": [
        'inurl:slot intitle:situs (gacor OR maxwin OR deposit)',
        'intitle:(judi OR togel OR bandar) inurl:wp-content',
        '카지노 inurl:wp-content',
    ],
    "exposed_files": [
        'inurl:wp-config.php.bak',
        'intitle:"index of" "wp-config.php"',
        'ext:sql intext:wp_users',
    ],
    "login_surfaces": [
        'inurl:wp-login.php intitle:"Log In"',
        'inurl:xmlrpc.php intext:"XML-RPC server accepts POST requests only"',
    ],
}


def load_mine(path: str) -> set:
    out = set()
    with open(path) as f:
        for line in f:
            d = line.strip()
            if not d or d.startswith("#"):
                continue
            d = d.replace("https://", "").replace("http://", "").split("/")[0]
            out.add(d.lower())
    return out


def registrable_match(host: str, mine: set) -> str:
    """Return the owned domain if host equals it or is a subdomain of it."""
    if not host:
        return ""
    host = host.lower()
    for m in mine:
        if host == m or host.endswith("." + m):
            return m
    return ""


def domain_of(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


_HOST_RE = __import__("re").compile(r"^[a-z0-9]([a-z0-9\-]{0,62}\.)+[a-z]{2,63}$")


def clean_host(s: str) -> str:
    """Normalize a candidate hostname; return '' if it isn't one.

    Strips cert-SAN wildcards ('*.') and rejects noise like ASN org names
    ('AMAZON-02 - Amazon.com') that carry spaces or aren't valid domains.
    """
    if not isinstance(s, str):
        return ""
    h = s.strip().lower().lstrip("*.").rstrip(".")
    if " " in h or "/" in h or not _HOST_RE.match(h):
        return ""
    return h


# --------------------------- Shodan engine ---------------------------------

def shodan_apiinfo(key: str) -> dict:
    r = requests.get("https://api.shodan.io/api-info", params={"key": key}, timeout=20)
    r.raise_for_status()
    return r.json()


def shodan_search(query: str, key: str, page: int) -> dict:
    """One page of Shodan search (100 results/page). Uses 1 query credit."""
    try:
        r = requests.get("https://api.shodan.io/shodan/host/search",
                         params={"key": key, "query": query, "page": page}, timeout=45)
        if r.status_code in (401, 403):
            return {"matches": [], "total": 0,
                    "error": f"{r.status_code}: {r.text[:160]}"}
        r.raise_for_status()
        data = r.json()
        return {"matches": data.get("matches", []),
                "total": data.get("total", 0), "error": None}
    except Exception as e:
        return {"matches": [], "total": 0, "error": f"{e.__class__.__name__}: {e}"}


def run_shodan(args, mine: set, ts: str) -> None:
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        sys.exit("SHODAN_API_KEY not set.  export SHODAN_API_KEY=...  (from shodan.io Account page)")

    # --test / credential + plan check (free, uses no query credits)
    try:
        info = shodan_apiinfo(key)
    except Exception as e:
        sys.exit(f"[!] Shodan key check failed: {e}")
    print(f"[*] Shodan plan: {info.get('plan')} | query credits: {info.get('query_credits')} "
          f"| scan credits: {info.get('scan_credits')}")
    if args.test:
        print("[*] Key is valid. (Search API needs a paid membership + query credits.)")
        return
    if not info.get("query_credits"):
        print("[!] 0 query credits — the search API will return 403. "
              "A Shodan membership is required for host/search. Aborting harvest.")
        return

    harvested = defaultdict(list)   # host -> [records]
    your_hits, raw = [], []
    country = f'country:"{args.country}"' if args.country else ""

    # Build the query set
    queries = []
    if args.cn:
        # Estate-discovery: find YOUR OWN hosts via your TLS cert CN
        queries.append(("estate_by_cert", f'ssl.cert.subject.cn:"{args.cn}"'))
    for cat, tmpls in SHODAN_DORKS.items():
        if args.only and cat not in {c.strip() for c in args.only.split(",")}:
            continue
        for t in tmpls:
            queries.append((cat, t.format(country=country).strip()))

    print(f"[*] {len(queries)} query(ies) x up to {args.pages} page(s). "
          f"Each page = 1 query credit.\n")

    for cat, q in queries:
        for p in range(1, args.pages + 1):
            res = shodan_search(q, key, p)
            if res["error"]:
                print(f"    [{cat}] p{p}: err {res['error']}")
                break
            if not res["matches"]:
                break
            for m in res["matches"]:
                ip = m.get("ip_str", "")
                hosts = list(m.get("hostnames", [])) or []
                doms = list(m.get("domains", [])) or []
                title = (m.get("http") or {}).get("title") or ""
                for h in (hosts or [ip]):
                    rec = {"category": cat, "query": q, "host": h, "ip": ip,
                           "title": title, "domains": doms}
                    raw.append(rec)
                    harvested[h].append(rec)
                    owned = registrable_match(h, mine) or \
                            next((registrable_match(d, mine) for d in doms
                                  if registrable_match(d, mine)), "")
                    if owned:
                        rec["owned_domain"] = owned
                        your_hits.append(rec)
                        print(f"    [!!!] YOUR HOST SURFACED: {h} ({ip}) "
                              f"owned:{owned} under [{cat}]")
            print(f"    [{cat}] p{p}: {len(res['matches'])} matches "
                  f"(total avail {res['total']}, {len(harvested)} unique hosts so far)")
            time.sleep(args.delay)

    write_report(ts, "shodan", harvested, your_hits, raw)


# --------------------------- Censys engine ---------------------------------

def _collect_hosts(obj, ips: set, names: set) -> None:
    """Recursively pull IPs and DNS names out of an arbitrary Censys hit object.

    Defensive: the Platform response schema nests differently across resource
    types, so we walk the whole structure rather than hardcode a path.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "ip" and isinstance(v, str):
                ips.add(v)
            elif k in ("names", "dns_names", "reverse_dns_names") and isinstance(v, list):
                names.update(c for x in v if (c := clean_host(x)))
            elif k in ("name", "common_name", "dns", "host") and isinstance(v, str):
                if (c := clean_host(v)):
                    names.add(c)
            else:
                _collect_hosts(v, ips, names)
    elif isinstance(obj, list):
        for it in obj:
            _collect_hosts(it, ips, names)


def censys_search(query: str, pat: str, org: str, page_token: str) -> dict:
    """One page of Censys Platform global search. Returns hits + next token."""
    try:
        body = {"query": query, "page_size": 100}
        if page_token:
            body["page_token"] = page_token
        r = requests.post(
            "https://api.platform.censys.io/v3/global/search/query",
            headers={"Authorization": f"Bearer {pat}",
                     "X-Organization-ID": org,
                     "Content-Type": "application/json",
                     "Accept": "application/json"},
            json=body, timeout=45,
        )
        if r.status_code >= 400:
            return {"hits": [], "next": None, "error": f"{r.status_code}: {r.text[:240]}"}
        data = r.json()
        # Defensive: hits may live under result.hits / result.matched_services / hits
        result = data.get("result", data)
        hits = (result.get("hits") or result.get("matched_services")
                or result.get("resources") or [])
        nxt = (result.get("next_page_token") or result.get("next_page")
               or result.get("page_token"))
        return {"hits": hits, "next": nxt, "error": None, "raw_keys": list(result.keys())}
    except Exception as e:
        return {"hits": [], "next": None, "error": f"{e.__class__.__name__}: {e}"}


def run_censys(args, mine: set, ts: str) -> None:
    pat = os.environ.get("CENSYS_PAT")
    org = os.environ.get("CENSYS_ORG_ID") or args.org
    if not pat:
        sys.exit("CENSYS_PAT not set.  export CENSYS_PAT=...  (Platform Personal Access Token)")
    if not org:
        sys.exit("Organization ID required. export CENSYS_ORG_ID=... or pass --org "
                 "(it's the UUID in your platform.censys.io URL).")

    harvested = defaultdict(list)
    your_hits, raw = [], []
    country = f' and host.location.country_code="{args.country}"' if args.country else ""

    queries = []
    if args.query:                       # raw CenQL passthrough
        queries.append(("custom", args.query))
    if args.cn:                          # estate discovery by cert / dns name
        queries.append(("estate_by_cert",
                        f'host.services.tls.certificates.leaf_data.subject.common_name'
                        f'="{args.cn}" or host.dns.names="{args.cn}"'))
    if not args.query:
        for cat, tmpls in CENSYS_DORKS.items():
            if args.only and cat not in {c.strip() for c in args.only.split(",")}:
                continue
            for t in tmpls:
                queries.append((cat, t.format(country=country)))

    print(f"[*] {len(queries)} Censys query(ies) x up to {args.pages} page(s).\n")
    for cat, q in queries:
        token = ""
        for p in range(args.pages):
            res = censys_search(q, pat, org, token)
            if res["error"]:
                print(f"    [{cat}] p{p+1}: ERR {res['error']}")
                break
            if p == 0 and not res["hits"]:
                print(f"    [{cat}] p1: 0 hits (response keys: {res.get('raw_keys')})")
            for hit in res["hits"]:
                ips, names = set(), set()
                _collect_hosts(hit, ips, names)
                ip = next(iter(ips), "")
                for h in (names or {ip}):
                    rec = {"category": cat, "query": q, "host": h, "ip": ip,
                           "all_names": sorted(names)}
                    raw.append(rec)
                    harvested[h].append(rec)
                    owned = registrable_match(h, mine)
                    if owned:
                        rec["owned_domain"] = owned
                        your_hits.append(rec)
                        print(f"    [!!!] YOUR HOST SURFACED: {h} ({ip}) "
                              f"owned:{owned} under [{cat}]")
            print(f"    [{cat}] p{p+1}: {len(res['hits'])} hits "
                  f"({len(harvested)} unique hosts so far)")
            token = res["next"]
            if not token:
                break
            time.sleep(args.delay)

    write_report(ts, "censys", harvested, your_hits, raw)


# --------------------------- Netlas engine ---------------------------------

def netlas_search(query: str, key: str, start: int) -> dict:
    """One page of Netlas /api/responses/ search (~20 results/page). Free tier."""
    try:
        r = requests.get(
            "https://app.netlas.io/api/responses/",
            params={"q": query, "start": start},
            headers={"Authorization": f"Bearer {key}", "accept": "application/json"},
            timeout=45,
        )
        if r.status_code == 429:
            return {"items": [], "error": "rate_limited (60/min free tier)"}
        if r.status_code == 402:
            return {"items": [], "error": "402: out of free coins/quota"}
        if r.status_code >= 400:
            return {"items": [], "error": f"{r.status_code}: {r.text[:240]}"}
        return {"items": r.json().get("items", []), "error": None}
    except Exception as e:
        return {"items": [], "error": f"{e.__class__.__name__}: {e}"}


def run_netlas(args, mine: set, ts: str) -> None:
    key = os.environ.get("NETLAS_API_KEY")
    if not key:
        sys.exit("NETLAS_API_KEY not set.  export NETLAS_API_KEY=...  "
                 "(free key from app.netlas.io -> profile -> API key)")

    harvested = defaultdict(list)
    your_hits, raw = [], []
    country = f' AND geo.country:{args.country}' if args.country else ""

    queries = []
    if args.query:
        queries.append(("custom", args.query))
    if args.cn:
        # cert-field search is paywalled on Netlas free tier; host: wildcard is not.
        # Plain wildcard is fast; the "OR host:apex" variant is ~25s and flaky, so skip it.
        queries.append(("estate_by_host", f'host:*.{args.cn}'))
    # Broad dork library runs only when NOT doing a focused --cn/--query check
    if not args.query and not args.cn:
        for cat, tmpls in NETLAS_DORKS.items():
            if args.only and cat not in {c.strip() for c in args.only.split(",")}:
                continue
            for t in tmpls:
                queries.append((cat, t.format(country=country)))

    print(f"[*] {len(queries)} Netlas query(ies) x up to {args.pages} page(s) "
          f"(~20 results/page).\n")
    for cat, q in queries:
        for p in range(args.pages):
            res = netlas_search(q, key, start=p * 20)
            if res["error"]:
                print(f"    [{cat}] p{p+1}: ERR {res['error']}")
                break
            if not res["items"]:
                break
            for item in res["items"]:
                data = item.get("data", item)
                ips, names = set(), set()
                _collect_hosts(data, ips, names)
                ip = data.get("ip") or next(iter(ips), "")
                for h in (names or {ip}):
                    rec = {"category": cat, "query": q, "host": h, "ip": ip,
                           "all_names": sorted(names)}
                    raw.append(rec)
                    harvested[h].append(rec)
                    owned = registrable_match(h, mine)
                    if owned:
                        rec["owned_domain"] = owned
                        your_hits.append(rec)
                        print(f"    [!!!] YOUR HOST SURFACED: {h} ({ip}) "
                              f"owned:{owned} under [{cat}]")
            print(f"    [{cat}] p{p+1}: {len(res['items'])} results "
                  f"({len(harvested)} unique hosts so far)")
            time.sleep(max(args.delay, 1.0))   # stay under 60/min

    write_report(ts, "netlas", harvested, your_hits, raw)


# --------------------------- Google engine ---------------------------------

def google_search_page(query: str, key: str, cx: str, start: int) -> dict:
    try:
        r = requests.get("https://www.googleapis.com/customsearch/v1",
                         params={"key": key, "cx": cx, "q": query, "num": 10,
                                 "start": start}, timeout=30)
        if r.status_code == 429:
            return {"items": [], "error": "rate_limited"}
        r.raise_for_status()
        return {"items": [{"title": i.get("title"), "link": i.get("link")}
                          for i in r.json().get("items", [])], "error": None}
    except Exception as e:
        return {"items": [], "error": f"{e.__class__.__name__}: {e}"}


def run_google(args, mine: set, ts: str) -> None:
    key, cx = os.environ.get("GOOGLE_API_KEY"), os.environ.get("GOOGLE_CX")
    if not (key and cx):
        sys.exit("GOOGLE_API_KEY and GOOGLE_CX must be set (CX = entire-web search engine).")
    harvested = defaultdict(list)
    your_hits, raw = [], []
    for cat, tmpls in GOOGLE_DORKS.items():
        if args.only and cat not in {c.strip() for c in args.only.split(",")}:
            continue
        for q in tmpls:
            for p in range(args.pages):
                res = google_search_page(q, key, cx, 1 + p * 10)
                if res["error"] == "rate_limited":
                    print("[!] Google daily quota hit — stopping.")
                    write_report(ts, "google", harvested, your_hits, raw)
                    return
                if res["error"]:
                    print(f"    [{cat}]: err {res['error']}"); break
                for it in res["items"]:
                    h = domain_of(it["link"])
                    rec = {"category": cat, "query": q, "host": h,
                           "url": it["link"], "title": it["title"]}
                    raw.append(rec); harvested[h].append(rec)
                    owned = registrable_match(h, mine)
                    if owned:
                        rec["owned_domain"] = owned; your_hits.append(rec)
                        print(f"    [!!!] YOUR DOMAIN SURFACED: {h} owned:{owned}")
                print(f"    [{cat}] p{p+1}: {len(res['items'])} results "
                      f"({len(harvested)} unique hosts)")
                time.sleep(args.delay)
    write_report(ts, "google", harvested, your_hits, raw)


# --------------------------- shared report ---------------------------------

def write_report(ts, engine, harvested, your_hits, raw) -> None:
    json_path, md_path = f"scan-{ts}.json", f"scan-{ts}.md"
    with open(json_path, "w") as f:
        json.dump({"generated": ts, "engine": engine, "your_hits": your_hits,
                   "harvested_hosts": sorted(harvested.keys()), "raw": raw},
                  f, indent=2, ensure_ascii=False)
    with open(md_path, "w") as f:
        f.write(f"# Unscoped {engine} scan — {ts}\n\n")
        f.write(f"Unique hosts harvested: {len(harvested)}\n\n")
        f.write("## 🚨 YOUR domains/hosts that surfaced in exposed results\n\n")
        if your_hits:
            for h in your_hits:
                f.write(f"- **{h['host']}** (owned: `{h['owned_domain']}`) — "
                        f"[{h['category']}] `{h['query']}`"
                        + (f" — {h.get('url') or h.get('ip','')}\n"))
        else:
            f.write("_None of your domains appeared in the harvested pile. "
                    "(Caveat: results are capped per query — absence ≠ safety.)_\n")
        f.write("\n## All harvested hosts (attacker's raw target pile)\n\n")
        for host in sorted(harvested.keys()):
            cats = sorted({r["category"] for r in harvested[host]})
            f.write(f"- `{host}` — {', '.join(cats)}\n")
    print(f"\n[*] {len(your_hits)} of your hosts surfaced · {len(harvested)} total harvested.")
    print(f"[*] Reports:\n    {md_path}\n    {json_path}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Attacker's-eye internet-wide dork scan; flag your exposure.")
    ap.add_argument("--engine", choices=["shodan", "google", "censys", "netlas"], default="netlas")
    ap.add_argument("--mine", help="file of YOUR domains to flag in results")
    ap.add_argument("--pages", type=int, default=2, help="result pages per query")
    ap.add_argument("--country", help="2-letter code to scope harvest (e.g. ID)")
    ap.add_argument("--cn", help="find your own estate by TLS cert CN / DNS name (e.g. nzmweb.com)")
    ap.add_argument("--org", help="Censys Organization ID (or set CENSYS_ORG_ID)")
    ap.add_argument("--query", help="Censys: raw CenQL query passthrough (overrides the library)")
    ap.add_argument("--only", help="comma-separated categories to run")
    ap.add_argument("--test", action="store_true", help="Shodan: validate key + show plan, then exit")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between API calls")
    args = ap.parse_args()

    mine = load_mine(args.mine) if args.mine else set()
    if not args.test and not args.mine:
        sys.exit("--mine is required (except with --test).")
    if mine:
        print(f"[*] Cross-referencing against {len(mine)} owned domain(s).")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if args.engine == "shodan":
        run_shodan(args, mine, ts)
    elif args.engine == "censys":
        run_censys(args, mine, ts)
    elif args.engine == "netlas":
        run_netlas(args, mine, ts)
    else:
        run_google(args, mine, ts)


if __name__ == "__main__":
    main()
