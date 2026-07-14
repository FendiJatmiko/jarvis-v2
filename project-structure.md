````
freeln/
      ├── pentest-agent.py ← main entrypoint (v0.14.0)
      ├── pentest_agent.py → symlink to pentest-agent.py (lets Python `import pentest_agent`)
      ├── http_client.py ┐
      ├── learn.py         ┤ top-level modules the agent imports directly
      ├── agent_bridge.py ┘ (+ recon.py, scanner_dork.py, dork-check.py — sibling tools)
      │
      ├── wp/ ← the WordPress toolkit, now a proper package
      │ ├── __init__.py
      │ ├── fingerprint.py (WP + plugin/version detection)
      │ ├── match.py (version → recipe matching)
      │ ├── recipes.py (curated exploit recipe registry)
      │ ├── vulns.py (vuln lookup)
      │ ├── exploit.py (payload builder / uploader)
      │ ├── sqli.py (SQLi confirm/extract)
      │ ├── authshell.py credattack.py privesc.py verify.py plugins_common.py
      │
      ├── tests/ ← tests for the wp package (pytest)
      │ └── test_fingerprint.py test_sqli.py test_recipes.py … (10 files)
      ├── test_pentest_agent.py ┐ tests for top-level modules
      ├── test_http_client.py ┘ (stay at root, next to what they test)
      │
      ├── install.sh / install ← system-wide installer (identical copies)
      ├── Makefile ← installs scanner_dork.py as `scanner-dork` (separate tool)
      ├── pytest.ini ← makes `wp` importable in any pytest invocation
      └── requirements.txt ← requests>=2.25
      ```
````
