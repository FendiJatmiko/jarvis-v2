# test_wp_fingerprint.py
from unittest.mock import MagicMock
import wp_fingerprint

HOME_HTML = '''
<html><head><meta name="generator" content="WordPress 6.4.2" /></head>
<body>
<link rel="stylesheet" href="http://t/wp-content/plugins/wp-file-manager/css/a.css" />
<script src="http://t/wp-content/plugins/wp-file-manager/js/b.js"></script>
<link href="http://t/wp-content/themes/astra/style.css" />
</body></html>
'''

README = "=== WP File Manager ===\nStable tag: 6.0\nRequires at least: 4.0\n"

def _resp(text, status=200):
    r = MagicMock()
    r.text = text
    r.status_code = status
    return r

def test_detects_wordpress_and_version():
    http = MagicMock()
    http.get.side_effect = lambda url, **kw: _resp(HOME_HTML) if url.endswith(("/", "t")) or "plugins" not in url else _resp(README)
    info = wp_fingerprint.fingerprint("http://t", http)
    assert info["is_wordpress"] is True
    assert info["version"] == "6.4.2"

def test_enumerates_plugin_and_version():
    def getter(url, **kw):
        if "readme.txt" in url:
            return _resp(README)
        return _resp(HOME_HTML)
    http = MagicMock(); http.get.side_effect = getter
    info = wp_fingerprint.fingerprint("http://t", http)
    slugs = {p["slug"]: p["version"] for p in info["plugins"]}
    assert slugs.get("wp-file-manager") == "6.0"
    assert info["theme"] == "astra"

def test_non_wordpress_site():
    http = MagicMock(); http.get.side_effect = lambda url, **kw: _resp("<html>hello</html>")
    info = wp_fingerprint.fingerprint("http://t", http)
    assert info["is_wordpress"] is False
    assert info["plugins"] == []
