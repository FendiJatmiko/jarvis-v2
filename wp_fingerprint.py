import re


def _get_text(http, url):
    try:
        return http.get(url).text or ""
    except Exception:
        return ""


def fingerprint(base_url, http):
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

    plugins = []
    slugs = sorted(set(re.findall(r"/wp-content/plugins/([\w-]+)/", home)))
    for slug in slugs:
        readme = _get_text(http, f"{base}/wp-content/plugins/{slug}/readme.txt")
        vm = re.search(r"Stable tag:\s*([\d.]+)", readme)
        plugins.append({"slug": slug, "version": vm.group(1) if vm else ""})

    return {"is_wordpress": is_wp, "version": version, "plugins": plugins, "theme": theme}
