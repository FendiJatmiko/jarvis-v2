"""Structural invariants for scanner_dork's dork tables.

We can't unit-test whether a Shodan/Censys/Netlas filter is *semantically* valid
without spending query credits, but we CAN guarantee the tables are well-formed:
every template is a non-empty string, country-scopable engines carry the
{country} placeholder so --country actually filters, and the new categories the
operator asked for are present on the primary (Shodan) engine.
"""
import importlib.util
import pathlib

_spec = importlib.util.spec_from_file_location(
    "scanner_dork", pathlib.Path(__file__).with_name("scanner_dork.py"))
scanner_dork = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner_dork)

# engines that support host.location country scoping via {country}
COUNTRY_ENGINES = {
    "SHODAN_DORKS": scanner_dork.SHODAN_DORKS,
    "CENSYS_DORKS": scanner_dork.CENSYS_DORKS,
    "NETLAS_DORKS": scanner_dork.NETLAS_DORKS,
}
NEW_CATEGORIES = {
    "exposed_databases", "unfinished_install", "admin_panels", "compromised_markers",
}


def test_all_templates_are_nonempty_strings():
    tables = dict(COUNTRY_ENGINES, GOOGLE_DORKS=scanner_dork.GOOGLE_DORKS)
    for name, table in tables.items():
        for cat, templates in table.items():
            assert templates, f"{name}[{cat}] is empty"
            for t in templates:
                assert isinstance(t, str) and t.strip(), f"{name}[{cat}] bad template {t!r}"


def test_country_engines_carry_country_placeholder():
    # Every country-engine template must format cleanly AND scope by country,
    # otherwise --country ID silently scans the whole internet for that dork.
    for name, table in COUNTRY_ENGINES.items():
        for cat, templates in table.items():
            for t in templates:
                assert "{country}" in t, f"{name}[{cat}] missing {{country}}: {t!r}"
                # must not blow up when filled or emptied
                t.format(country='country:"ID"')
                t.format(country="")


def test_new_categories_present_on_shodan():
    for cat in NEW_CATEGORIES:
        assert cat in scanner_dork.SHODAN_DORKS, f"Shodan missing new category {cat}"


def test_exposed_databases_covers_the_big_five():
    blob = " ".join(scanner_dork.SHODAN_DORKS["exposed_databases"]).lower()
    for db in ("mysql", "mongodb", "redis", "postgresql", "elastic"):
        assert db in blob, f"exposed_databases missing {db}"
