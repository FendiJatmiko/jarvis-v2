import re

import wp_recipes
import wp_plugins_common


def _fetch(http, url):
    """Return (status_code, text), swallowing any transport error."""
    try:
        r = http.get(url)
        return getattr(r, "status_code", 200), (r.text or "")
    except Exception:
        return 0, ""


def _get_text(http, url):
    return _fetch(http, url)[1]


def _looks_like_readme(text):
    """Heuristic: a real WordPress plugin readme.txt, not a soft-404 page."""
    return ("Stable tag:" in text) or ("Requires at least:" in text) \
        or bool(re.match(r"\s*===", text))


def _probe_plugin(http, base, slug):
    """Actively probe a plugin's readme.txt. Returns {slug, version} if the
    plugin appears installed (real readme on a 200), else None. This finds
    admin-only plugins (e.g. File Manager) that leave no front-end footprint."""
    status, text = _fetch(http, f"{base}/wp-content/plugins/{slug}/readme.txt")
    if status == 200 and _looks_like_readme(text):
        vm = re.search(r"Stable tag:\s*([\d.]+)", text)
        return {"slug": slug, "version": vm.group(1) if vm else ""}
    return None


def fingerprint(base_url, http, probe_slugs=None):
    base = base_url.rstrip("/")
    home = _get_text(http, base + "/")

    is_wp = ("/wp-content/" in home) or ("wp-json" in home) or \
            bool(re.search(r'name=["\']generator["\']\s+content=["\']WordPress', home))

    version = None
    m = re.search(r'content=["\']WordPress\s+([\d.]+)', home)
    if m:
        version = m.group(1)

    theme = None
    tm = re.search(r"/wp-content/themes/([\w-]+)/", home)
    if tm:
        theme = tm.group(1)

    # Candidate slugs = plugins referenced on the home page (passive) UNION the
    # slugs we have exploit recipes for (active). Active probing is what lets us
    # detect admin-only vulnerable plugins with no front-end assets.
    passive = set(re.findall(r"/wp-content/plugins/([\w-]+)/", home))
    if probe_slugs is None:
        # everything we can exploit UNION the common/high-risk stack, so Track A
        # sees the real installed plugins, not just the ones we have recipes for.
        probe_slugs = {r["plugin"] for r in wp_recipes.RECIPES} \
            | set(wp_plugins_common.COMMON_SLUGS)

    plugins = []
    for slug in sorted(passive | set(probe_slugs)):
        probed = _probe_plugin(http, base, slug)
        if probed:
            plugins.append(probed)
        elif slug in passive:
            # Referenced on the home page but readme not reachable — record
            # it best-effort so downstream still sees the plugin exists.
            plugins.append({"slug": slug, "version": ""})

    return {"is_wordpress": is_wp, "version": version, "plugins": plugins, "theme": theme}
