"""Structural invariants for scanner_dork's Shodan dork table.

We can't unit-test whether a Shodan filter is *semantically* valid without
spending query credits, but we CAN guarantee the table is well-formed: every
template is a non-empty string, it carries the {country} placeholder so
--country actually filters, and the new categories the operator asked for
are present.
"""
import importlib.util
import pathlib

_spec = importlib.util.spec_from_file_location(
    "scanner_dork", pathlib.Path(__file__).with_name("scanner_dork.py"))
scanner_dork = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner_dork)

NEW_CATEGORIES = {
    "exposed_databases", "unfinished_install", "admin_panels", "compromised_markers",
}


def test_all_templates_are_nonempty_strings():
    for cat, templates in scanner_dork.SHODAN_DORKS.items():
        assert templates, f"SHODAN_DORKS[{cat}] is empty"
        for t in templates:
            assert isinstance(t, str) and t.strip(), f"SHODAN_DORKS[{cat}] bad template {t!r}"


def test_shodan_dorks_carry_country_placeholder():
    # Every template must format cleanly AND scope by country, otherwise
    # --country ID silently scans the whole internet for that dork.
    for cat, templates in scanner_dork.SHODAN_DORKS.items():
        for t in templates:
            assert "{country}" in t, f"SHODAN_DORKS[{cat}] missing {{country}}: {t!r}"
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


def test_http_url_scheme_and_port():
    u = scanner_dork._http_url
    assert u("site.com", 443, True) == "https://site.com"       # tls, standard port hidden
    assert u("site.com", 80, False) == "http://site.com"        # plain, standard port hidden
    assert u("site.com", 8080, False) == "http://site.com:8080"  # non-standard shown
    assert u("site.com", 8443, True) == "https://site.com:8443"
    assert u("1.2.3.4", None, True) == "https://1.2.3.4"        # missing port tolerated


def test_shodan_tls_detection_signals():
    # mirror the inline detection: an `ssl` block OR an https module => https
    def is_tls(m):
        return ("ssl" in m) or ("https" in str((m.get("_shodan") or {}).get("module", "")))
    assert is_tls({"ssl": {"versions": ["TLSv1.3"]}, "port": 443}) is True
    assert is_tls({"_shodan": {"module": "https"}, "port": 443}) is True
    assert is_tls({"_shodan": {"module": "http-simple-new"}, "port": 80}) is False
    assert is_tls({"port": 80}) is False


# --- Task 6: --exploit argument validation -------------------------------
import types


def _args(**kw):
    base = dict(exploit=False, mine=None,
                agent_path="scanner_dork.py")  # a file that exists
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_exploit_requires_mine():
    err = scanner_dork.exploit_arg_error(_args(exploit=True, mine=None))
    assert err and "--mine" in err


def test_exploit_missing_agent_path():
    err = scanner_dork.exploit_arg_error(
        _args(exploit=True, mine="domains.txt", agent_path="/no/such/file"))
    assert err and "agent-path" in err


def test_exploit_args_ok_returns_none():
    assert scanner_dork.exploit_arg_error(
        _args(exploit=True, mine="domains.txt")) is None


def test_no_exploit_never_errors():
    assert scanner_dork.exploit_arg_error(_args(exploit=False)) is None


# --- Shodan vuln/version enrichment ---------------------------------------
def test_vuln_hints_extracts_cves_product_version():
    m = {"product": "nginx", "version": "1.18.0",
         "vulns": {"CVE-2021-23017": {"cvss": 8.1}, "CVE-2019-9511": {}}}
    h = scanner_dork.vuln_hints(m)
    assert h["cves"] == ["CVE-2019-9511", "CVE-2021-23017"]   # sorted
    assert h["product"] == "nginx" and h["version"] == "1.18.0"


def test_vuln_hints_filters_shodan_excluded_marker():
    # Shodan prefixes NOT-applicable CVEs with '!'
    m = {"vulns": {"CVE-2020-0001": {}, "!CVE-2000-0000": {}}}
    assert scanner_dork.vuln_hints(m)["cves"] == ["CVE-2020-0001"]


def test_vuln_hints_empty_when_no_data():
    h = scanner_dork.vuln_hints({})
    assert h["cves"] == [] and h["product"] == "" and h["version"] == ""


def test_hint_label_builds_bracket():
    lbl = scanner_dork.hint_label(
        {"product": "OpenSSH", "version": "7.4", "cves": ["CVE-2018-15473"]})
    assert "OpenSSH 7.4" in lbl and "possible CVE-2018-15473" in lbl
    assert lbl.startswith(" [") and lbl.endswith("]")


def test_hint_label_empty_when_nothing():
    assert scanner_dork.hint_label({"product": "", "version": "", "cves": []}) == ""


# --- --query raw passthrough / build_queries ------------------------------
def _qargs(**kw):
    base = dict(query=None, cn=None, only=None, nets=[], net_batch=10)
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_build_queries_default_runs_full_catalog():
    qs = scanner_dork.build_queries(_qargs(), country="")
    cats = {c for c, _ in qs}
    assert cats == set(scanner_dork.SHODAN_DORKS)   # every dork category, nothing else
    assert "custom" not in cats


def test_build_queries_only_filters_catalog():
    qs = scanner_dork.build_queries(_qargs(only="exposed_databases"), country="")
    assert {c for c, _ in qs} == {"exposed_databases"}


def test_build_queries_raw_overrides_catalog():
    # --query replaces the whole catalog with ONE custom query (don't burn
    # credits on every category when the operator asked for a specific one).
    qs = scanner_dork.build_queries(_qargs(query='http.html:"revslider"'), country="")
    assert [c for c, _ in qs] == ["custom"]
    assert qs[0][1] == 'http.html:"revslider"'


def test_build_queries_raw_appends_country():
    qs = scanner_dork.build_queries(
        _qargs(query="vuln:CVE-2015-5151"), country='country:"ID"')
    assert len(qs) == 1
    cat, q = qs[0]
    assert cat == "custom"
    assert q == 'vuln:CVE-2015-5151 country:"ID"'


def test_build_queries_raw_still_composes_net_scope():
    qs = scanner_dork.build_queries(
        _qargs(query='product:"MySQL"', nets=["203.0.113.0/24"], net_batch=10),
        country="")
    assert len(qs) == 1
    assert qs[0][1] == 'product:"MySQL" net:203.0.113.0/24'


def test_build_queries_cn_runs_alongside_raw():
    # estate discovery (--cn) is orthogonal and still runs before the custom query
    qs = scanner_dork.build_queries(
        _qargs(query="vuln:CVE-1", cn="nzmweb.com"), country="")
    assert [c for c, _ in qs] == ["estate_by_cert", "custom"]
