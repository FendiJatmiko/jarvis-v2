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

  # Scope the harvest to one of YOUR public networks (CIDR) — see what's exposed there:
  python3 scanner_dork.py --engine netlas --mine assets.txt --net 203.0.113.0/24

  # Discover YOUR OWN estate via your TLS cert (great for a subdomain farm):
  python3 scanner_dork.py --engine shodan --mine domains.txt --cn nzmweb.com

  # Google engine (needs entire-web CX):
  python3 scanner_dork.py --engine google --mine domains.txt

The --mine file may mix domains and public IP ranges, one per line:
      example.com
      www.example.com
      203.0.113.0/24        # CIDR — any harvested host whose IP lands here is flagged
      198.51.100.7          # a bare IP is treated as a /32
  Name entries match by exact host or subdomain; CIDR/IP entries match by IP
  containment against each harvested record's resolved address.

Output:
  scan-<timestamp>.md   — YOUR matches highlighted first, then the raw harvested pile
  scan-<timestamp>.json — full machine-readable results
"""
import argparse
import ipaddress
import json
import os
import sys
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone

import requests

import agent_bridge

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
    # DBs speaking their native protocol straight to the internet. A --mine hit
    # here = your database is one `mysql -h` away from being dumped. Very noisy
    # internet-wide, but the cross-ref is what matters.
    "exposed_databases": [
        'product:"MySQL" port:3306 {country}',
        'product:"MongoDB" {country}',
        'product:"Redis" {country}',
        'product:"PostgreSQL" port:5432 {country}',
        'product:"Elastic" port:9200 {country}',
    ],
    # A WordPress whose install wizard is still reachable = one-click takeover,
    # no exploit. The wizard's own copy is the fingerprint.
    "unfinished_install": [
        'http.html:"five-minute WordPress installation" {country}',
        'http.html:"wp-admin/setup-config.php" {country}',
    ],
    # Server/DB control panels that should never face the internet.
    "admin_panels": [
        'http.title:"Adminer" {country}',
        'http.html:"cPanel" port:2083 {country}',
        'http.title:"Webmin" {country}',
    ],
    # Already-owned markers OTHER than gambling: live webshell panels (WSO /
    # IndoXploit / b374k), pharma-spam injection. A hit is an incident.
    "compromised_markers": [
        'http.title:"WSO" http.html:"wp-content" {country}',
        'http.html:"IndoXploit" {country}',
        'http.html:"b374k" {country}',
        'http.html:"cialis" http.component:"WordPress" {country}',
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
    "exposed_databases": [
        'host.services.service_name="MYSQL"{country}',
        'host.services.service_name="MONGODB"{country}',
        'host.services.service_name="REDIS"{country}',
        'host.services.service_name="ELASTICSEARCH"{country}',
        'host.services.service_name="POSTGRES"{country}',
    ],
    "unfinished_install": [
        'host.services.http.response.body:"five-minute WordPress installation"{country}',
    ],
    "admin_panels": [
        'host.services.http.response.html_title="Adminer"{country}',
        'host.services.http.response.html_title:"Webmin"{country}',
    ],
    "compromised_markers": [
        'host.services.http.response.body:"IndoXploit"{country}',
        'host.services.http.response.html_title:"WSO"{country}',
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
    "exposed_databases": [
        'port:3306{country}',
        'port:27017{country}',
        'port:6379{country}',
        'port:9200{country}',
        'port:5432{country}',
    ],
    "unfinished_install": [
        'http.body:"five-minute WordPress installation"{country}',
    ],
    "admin_panels": [
        'http.title:"Adminer"{country}',
        'http.title:"Webmin"{country}',
    ],
    "compromised_markers": [
        'http.body:"IndoXploit"{country}',
        'http.title:"WSO"{country}',
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
    "unfinished_install": [
        'inurl:wp-admin/install.php intitle:"WordPress"',
        'inurl:wp-admin/setup-config.php',
    ],
    "admin_panels": [
        'intitle:"Adminer" inurl:adminer',
    ],
    "compromised_markers": [
        'intitle:"IndoXploit"',
        'intitle:"WSO" inurl:.php',
        'intext:"buy cialis" inurl:wp-content',
    ],
}


class Mine:
    """Owned assets to cross-reference against harvested hosts.

    Holds two kinds of entries parsed from the --mine file:
      * registrable domains / hostnames  -> matched by name (exact or subdomain)
      * IP networks (CIDR) / bare IPs     -> matched by IP containment

    A bare IP is stored as a /32 (or /128) network, so it still matches on the
    `ip` field of a harvested record even when the record carries no hostname.
    """

    def __init__(self):
        self.domains = set()      # lowercased registrable domains / hosts
        self.networks = []        # list[IPv4Network | IPv6Network]

    def add(self, entry: str) -> None:
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            return
        entry = entry.replace("https://", "").replace("http://", "")
        # CIDR or bare IP?  ip_network(strict=False) accepts both (bare -> /32).
        try:
            self.networks.append(ipaddress.ip_network(entry, strict=False))
            return
        except ValueError:
            pass
        host = entry.split("/")[0].strip().lower()   # drop any URL path
        if host:
            self.domains.add(host)

    def _match_ip(self, s: str) -> str:
        if not s or not self.networks:
            return ""
        try:
            addr = ipaddress.ip_address(s.strip())
        except ValueError:
            return ""
        for net in self.networks:
            if addr in net:
                return str(net)
        return ""

    def match(self, host: str = "", ip: str = "", extra_domains=()) -> str:
        """Return the owned identifier (domain or CIDR) this record belongs to."""
        for cand in (host, *extra_domains):
            m = registrable_match(cand, self.domains)
            if m:
                return m
        for cand in (ip, host):
            m = self._match_ip(cand)
            if m:
                return m
        return ""

    def __len__(self):
        return len(self.domains) + len(self.networks)

    def __bool__(self):
        return bool(self.domains or self.networks)


def exploit_arg_error(args):
    """Return an error string if --exploit is misused, else None. Enforces the
    owned-only + shodan-only invariants BEFORE any scan runs."""
    if not getattr(args, "exploit", False):
        return None
    if not args.mine:
        return ("--exploit requires --mine — only your cross-referenced hosts "
                "are exploited, never the harvested pile")
    if args.engine != "shodan":
        return "--exploit is supported only with --engine shodan"
    if not os.path.exists(args.agent_path):
        return f"--agent-path not found: {args.agent_path}"
    return None


def load_mine(path: str) -> Mine:
    mine = Mine()
    with open(path) as f:
        for line in f:
            mine.add(line)
    return mine


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


def _valid_cidr(s: str) -> str:
    """Canonicalize a CIDR / bare IP, or exit with a clear error."""
    try:
        return str(ipaddress.ip_network(s, strict=False))
    except ValueError as e:
        sys.exit(f"--net: {s!r} is not a valid CIDR/IP ({e})")


def parse_nets(spec: str) -> list:
    """Expand a --net value into a deduped list of canonical CIDRs.

    Accepts a comma-separated list, a path to a wordlist file (one CIDR/IP per
    line, '#' comments allowed), or any mix of the two:
        --net 27.111.32.0/20,10.12.33.0/24
        --net ranges.txt
        --net ranges.txt,203.0.113.0/24
    """
    out, seen = [], set()
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok:
            continue
        items = []
        if os.path.isfile(tok):
            with open(tok) as f:
                for line in f:
                    line = line.split("#")[0].strip()
                    if line:
                        items.append(line)
        else:
            items.append(tok)
        for it in items:
            cidr = _valid_cidr(it)
            if cidr not in seen:
                seen.add(cidr)
                out.append(cidr)
    return out


def net_chunks(nets: list, size: int):
    """Yield the net list in chunks of `size`; a single empty chunk if no nets.

    Search engines cap how many filters one query may carry, so a big --net
    list is split across several queries rather than OR'd into one that the
    API rejects (Netlas: 'Too many search filters provided.').
    """
    if not nets:
        yield []
        return
    size = max(1, size)
    for i in range(0, len(nets), size):
        yield nets[i:i + size]


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

def _http_url(host: str, port, is_tls: bool) -> str:
    """Reconstruct the browsable URL. Keeps the port only when non-standard so
    https://site and http://site:8080 both read cleanly."""
    scheme = "https" if is_tls else "http"
    if port and int(port) not in (80, 443):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


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
            base = t.format(country=country).strip()
            for chunk in net_chunks(args.nets, args.net_batch):
                q = f"{base} net:{','.join(chunk)}".strip() if chunk else base
                queries.append((cat, q))

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
                # Shodan flags TLS with an `ssl` block; the module name ("https",
                # "http-simple-new", ...) is the fallback signal. Port disambiguates.
                port = m.get("port")
                is_tls = ("ssl" in m) or ("https" in str((m.get("_shodan") or {}).get("module", "")))
                scheme = "https" if is_tls else "http"
                for h in (hosts or [ip]):
                    rec = {"category": cat, "query": q, "host": h, "ip": ip,
                           "title": title, "domains": doms,
                           "port": port, "scheme": scheme,
                           "url": _http_url(h, port, is_tls)}
                    raw.append(rec)
                    harvested[h].append(rec)
                    owned = mine.match(h, ip, doms)
                    if owned:
                        rec["owned_domain"] = owned
                        your_hits.append(rec)
                        print(f"    [!!!] YOUR HOST SURFACED: {rec['url']} ({ip}) "
                              f"owned:{owned} under [{cat}]")
            print(f"    [{cat}] p{p}: {len(res['matches'])} matches "
                  f"(total avail {res['total']}, {len(harvested)} unique hosts so far)")
            time.sleep(args.delay)

    write_report(ts, "shodan", harvested, your_hits, raw, cross_ref=bool(mine))

    if getattr(args, "exploit", False):
        results = agent_bridge.run_exploitation(
            your_hits, mode=args.exploit_mode, agent_path=args.agent_path,
            timeout=args.exploit_timeout, dry_run=args.exploit_dry_run)
        if not args.exploit_dry_run:
            agent_bridge.write_exploit_report(ts, results)


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
                base = t.format(country=country)
                for chunk in net_chunks(args.nets, args.net_batch):
                    q = base
                    if chunk:
                        ors = " or ".join(f"host.ip: {n}" for n in chunk)
                        q = f"{q} and ({ors})"
                    queries.append((cat, q))

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
                    owned = mine.match(h, ip)
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

    write_report(ts, "censys", harvested, your_hits, raw, cross_ref=bool(mine))


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
                base = t.format(country=country)
                for chunk in net_chunks(args.nets, args.net_batch):
                    q = base
                    if chunk:
                        ors = " OR ".join(f'ip:"{n}"' for n in chunk)   # quote: Netlas 500s on bare CIDR
                        q = f"{q} AND ({ors})"
                    queries.append((cat, q))

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
                    owned = mine.match(h, ip)
                    if owned:
                        rec["owned_domain"] = owned
                        your_hits.append(rec)
                        print(f"    [!!!] YOUR HOST SURFACED: {h} ({ip}) "
                              f"owned:{owned} under [{cat}]")
            print(f"    [{cat}] p{p+1}: {len(res['items'])} results "
                  f"({len(harvested)} unique hosts so far)")
            time.sleep(max(args.delay, 1.0))   # stay under 60/min

    write_report(ts, "netlas", harvested, your_hits, raw, cross_ref=bool(mine))


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
                    write_report(ts, "google", harvested, your_hits, raw, cross_ref=bool(mine))
                    return
                if res["error"]:
                    print(f"    [{cat}]: err {res['error']}"); break
                for it in res["items"]:
                    h = domain_of(it["link"])
                    rec = {"category": cat, "query": q, "host": h,
                           "url": it["link"], "title": it["title"]}
                    raw.append(rec); harvested[h].append(rec)
                    owned = mine.match(h)
                    if owned:
                        rec["owned_domain"] = owned; your_hits.append(rec)
                        print(f"    [!!!] YOUR DOMAIN SURFACED: {h} owned:{owned}")
                print(f"    [{cat}] p{p+1}: {len(res['items'])} results "
                      f"({len(harvested)} unique hosts)")
                time.sleep(args.delay)
    write_report(ts, "google", harvested, your_hits, raw, cross_ref=bool(mine))


# --------------------------- shared report ---------------------------------

def write_report(ts, engine, harvested, your_hits, raw, cross_ref=True) -> None:
    json_path, md_path = f"scan-{ts}.json", f"scan-{ts}.md"
    with open(json_path, "w") as f:
        json.dump({"generated": ts, "engine": engine, "cross_ref": cross_ref,
                   "your_hits": your_hits,
                   "harvested_hosts": sorted(harvested.keys()), "raw": raw},
                  f, indent=2, ensure_ascii=False)
    with open(md_path, "w") as f:
        f.write(f"# Unscoped {engine} scan — {ts}\n\n")
        f.write(f"Unique hosts harvested: {len(harvested)}\n\n")
        if cross_ref:
            f.write("## 🚨 YOUR domains/hosts that surfaced in exposed results\n\n")
            if your_hits:
                for h in your_hits:
                    f.write(f"- **{h['host']}** (owned: `{h['owned_domain']}`) — "
                            f"[{h['category']}] `{h['query']}`"
                            + (f" — {h.get('url') or h.get('ip','')}\n"))
            else:
                f.write("_None of your domains appeared in the harvested pile. "
                        "(Caveat: results are capped per query — absence ≠ safety.)_\n")
        else:
            f.write("## Harvest-only run (no `--mine` cross-reference)\n\n")
            f.write("_Pass `--mine <file>` (domains and/or public CIDRs) to flag your own "
                    "assets in the pile below._\n")
        f.write("\n## All harvested hosts (attacker's raw target pile)\n\n")
        for host in sorted(harvested.keys()):
            recs = harvested[host]
            cats = sorted({r["category"] for r in recs})
            # Prefer the reconstructed URL(s) (scheme + non-standard port) so the
            # reader sees http:// vs https:// at a glance; fall back to bare host
            # for engines that don't yet populate a url.
            urls = sorted({r.get("url") for r in recs if r.get("url")})
            label = " , ".join(urls) if urls else f"`{host}`"
            f.write(f"- {label} — {', '.join(cats)}\n")
    if cross_ref:
        print(f"\n[*] {len(your_hits)} of your hosts surfaced · {len(harvested)} total harvested.")
    else:
        print(f"\n[*] {len(harvested)} hosts harvested (no --mine cross-reference).")
    print(f"[*] Reports:\n    {md_path}\n    {json_path}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Attacker's-eye internet-wide dork scan; flag your exposure.")
    ap.add_argument("--engine", choices=["shodan", "google", "censys", "netlas"], default="netlas")
    ap.add_argument("--mine", help="optional file of YOUR domains and/or public CIDRs to flag "
                                    "in results; omit for a harvest-only run")
    ap.add_argument("--pages", type=int, default=2, help="result pages per query")
    ap.add_argument("--country", help="2-letter code to scope harvest (e.g. ID)")
    ap.add_argument("--net", help="scope the harvest to one or more public networks: a single "
                                  "CIDR, a comma-separated list, and/or a wordlist file "
                                  "(e.g. 203.0.113.0/24,198.51.100.0/24 or ranges.txt). "
                                  "shodan/censys/netlas only.")
    ap.add_argument("--net-batch", type=int, default=10, dest="net_batch",
                    help="max CIDRs OR'd into a single query; larger --net lists are split "
                         "into this many per query (default 10; lower it if you hit "
                         "'Too many search filters')")
    ap.add_argument("--cn", help="find your own estate by TLS cert CN / DNS name (e.g. nzmweb.com)")
    ap.add_argument("--org", help="Censys Organization ID (or set CENSYS_ORG_ID)")
    ap.add_argument("--query", help="Censys: raw CenQL query passthrough (overrides the library)")
    ap.add_argument("--only", help="comma-separated categories to run")
    ap.add_argument("--test", action="store_true", help="Shodan: validate key + show plan, then exit")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between API calls")
    ap.add_argument("--exploit", action="store_true",
                    help="after scan, hand YOUR surfaced hosts to pentest-agent (requires --mine)")
    ap.add_argument("--exploit-mode", choices=["auto", "plan", "safe"],
                    default="auto", dest="exploit_mode")
    ap.add_argument("--exploit-dry-run", action="store_true", dest="exploit_dry_run",
                    help="list the hosts that would be exploited, run nothing")
    ap.add_argument("--agent-path", default="./pentest-agent.py", dest="agent_path")
    ap.add_argument("--exploit-timeout", type=int, default=600, dest="exploit_timeout")
    args = ap.parse_args()

    _exploit_err = exploit_arg_error(args)
    if _exploit_err:
        ap.error(_exploit_err)

    args.nets = parse_nets(args.net) if args.net else []
    if args.nets:
        if args.engine == "google":
            print("[!] --net is ignored for the google engine (no IP-range filter).")
        else:
            print(f"[*] Scoping harvest to {len(args.nets)} network(s): {', '.join(args.nets)}")
            if len(args.nets) > args.net_batch:
                chunks = -(-len(args.nets) // args.net_batch)   # ceil div
                print(f"[*] >{args.net_batch} networks: each dork is split into {chunks} "
                      f"net-chunks — multiplies query count (mind API credits / daily limits).")

    mine = load_mine(args.mine) if args.mine else Mine()
    if mine:
        print(f"[*] Cross-referencing against {len(mine.domains)} owned domain(s) "
              f"and {len(mine.networks)} network(s).")
    elif not args.test:
        print("[*] No --mine file: harvest-only run "
              "(results won't be cross-referenced against your assets).")

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
