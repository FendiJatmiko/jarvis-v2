# test_wp_recipes.py
import wp_recipes

def test_file_manager_recipe_present():
    recs = wp_recipes.find_recipes("wp-file-manager")
    assert len(recs) >= 1
    r = recs[0]
    assert r["cve"] == "CVE-2020-25213"
    assert r["affected"] == "<=6.8"
    assert r["endpoint"] == "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
    assert r["field"] == "upload[]"
    assert "{filename}" in r["upload_path"]
    assert r["source"] == "registry"

def test_find_unknown_returns_empty():
    assert wp_recipes.find_recipes("does-not-exist") == []

def test_all_recipes_have_required_keys():
    required = {"plugin","cve","affected","method","endpoint","params","field","upload_path","source","note"}
    for r in wp_recipes.RECIPES:
        assert required <= set(r.keys()), f"missing keys in {r.get('plugin')}"
