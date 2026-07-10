# test_agent_bridge.py
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
