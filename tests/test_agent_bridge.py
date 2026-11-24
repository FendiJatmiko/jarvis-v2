# test_agent_bridge.py
import json
import subprocess

import agent_bridge


def test_dedupe_collapses_multi_category_host():
    your_hits = [
        {"host": "b.com", "url": "https://b.com", "category": "login_surfaces"},
        {"host": "b.com", "url": "https://b.com", "category": "exposed_databases"},
        {"host": "a.com", "url": "http://a.com:8080", "category": "admin_panels"},
    ]
    out = agent_bridge.dedupe_targets(your_hits)
    assert out == [
        {"host": "a.com", "url": "http://a.com:8080", "categories": ["admin_panels"]},
        {"host": "b.com", "url": "https://b.com",
         "categories": ["exposed_databases", "login_surfaces"]},
    ]


def test_dedupe_empty():
    assert agent_bridge.dedupe_targets([]) == []


def test_build_argv():
    assert agent_bridge.build_argv(
        "https://x.com", "auto", "./pentest-agent.py"
    ) == ["python3", "./pentest-agent.py", "https://x.com", "--mode", "auto"]


def test_parse_verdict_shell_from_verify_marker():
    out = "[VERIFY] ✅ WEBSHELL CONFIRMED via 'php.jpg'\n"
    assert agent_bridge.parse_verdict(out, 0) == "shell"


def test_parse_verdict_shell_from_trackb_marker():
    out = "[TRACK-B] ✅ WEBSHELL via authenticated plugin upload (lastudio)\n"
    assert agent_bridge.parse_verdict(out, 0) == "shell"


def test_parse_verdict_shell_wins_over_nonzero_rc():
    assert agent_bridge.parse_verdict("WEBSHELL CONFIRMED via 'x'", 1) == "shell"


def test_parse_verdict_error_on_nonzero_rc():
    assert agent_bridge.parse_verdict("some traceback", 1) == "error"


def test_parse_verdict_clean():
    assert agent_bridge.parse_verdict("no webshell path found", 0) == "clean"


class _FakeCompleted:
    def __init__(self, stdout, returncode):
        self.stdout = stdout
        self.returncode = returncode


def test_run_exploitation_records_shell_and_clean():
    hits = [
        {"host": "shell.com", "url": "https://shell.com", "category": "login_surfaces"},
        {"host": "clean.com", "url": "https://clean.com", "category": "wordpress_hosts"},
    ]
    calls = []

    def fake_runner(argv, **kw):
        calls.append(argv)
        if "shell.com" in argv[2]:
            return _FakeCompleted("[VERIFY] ✅ WEBSHELL CONFIRMED via 'x'", 0)
        return _FakeCompleted("no path", 0)

    results = agent_bridge.run_exploitation(
        hits, mode="auto", runner=fake_runner, log=lambda *_: None)
    verdicts = {r["host"]: r["verdict"] for r in results}
    assert verdicts == {"shell.com": "shell", "clean.com": "clean"}
    # sequential, one call per unique host, correct argv shape
    assert calls[0][:2] == ["python3", "./pentest-agent.py"]


def test_run_exploitation_dry_run_spawns_nothing():
    hits = [{"host": "a.com", "url": "https://a.com", "category": "login_surfaces"}]
    spawned = []
    results = agent_bridge.run_exploitation(
        hits, dry_run=True, runner=lambda *a, **k: spawned.append(a),
        log=lambda *_: None)
    assert spawned == []
    assert results[0]["verdict"] == "dry-run"


def test_run_exploitation_timeout_does_not_abort_sweep():
    hits = [
        {"host": "slow.com", "url": "https://slow.com", "category": "login_surfaces"},
        {"host": "ok.com", "url": "https://ok.com", "category": "login_surfaces"},
    ]

    def fake_runner(argv, **kw):
        if "slow.com" in argv[2]:
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        return _FakeCompleted("no path", 0)

    results = agent_bridge.run_exploitation(
        hits, runner=fake_runner, log=lambda *_: None)
    verdicts = {r["host"]: r["verdict"] for r in results}
    assert verdicts == {"slow.com": "timeout", "ok.com": "clean"}


def test_run_exploitation_empty_hits():
    assert agent_bridge.run_exploitation([], log=lambda *_: None) == []


def test_write_exploit_report_appends_md_and_json(tmp_path):
    ts = "TS"
    (tmp_path / f"scan-{ts}.md").write_text("# scan\n")
    (tmp_path / f"scan-{ts}.json").write_text(json.dumps({"engine": "shodan"}))
    results = [
        {"host": "a.com", "url": "https://a.com", "categories": ["login_surfaces"],
         "rc": 0, "verdict": "shell", "tail": "WEBSHELL CONFIRMED via 'x'"},
    ]
    agent_bridge.write_exploit_report(ts, results, report_dir=str(tmp_path))

    md = (tmp_path / f"scan-{ts}.md").read_text()
    assert "## Exploitation pass" in md
    assert "https://a.com" in md and "shell" in md

    data = json.loads((tmp_path / f"scan-{ts}.json").read_text())
    assert data["exploit_results"] == results
    assert data["engine"] == "shodan"  # original content preserved
