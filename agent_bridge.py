"""Bridge: hand the operator's OWN scan-surfaced hosts to pentest-agent.

Only ever operates on your_hits (the --mine cross-referenced pile). The raw
internet harvest is never touched here. pentest-agent v0.11.0 returns exit 0
regardless of outcome, so success is read from stdout markers, not the rc.
"""


def dedupe_targets(your_hits):
    """Collapse your_hits (one row per host*category) into unique hosts, each
    carrying the sorted set of categories it surfaced under."""
    by_host = {}
    for hit in your_hits:
        host = hit["host"]
        slot = by_host.setdefault(
            host, {"host": host, "url": hit["url"], "categories": set()})
        slot["categories"].add(hit["category"])
    out = []
    for host in sorted(by_host):
        slot = by_host[host]
        out.append({"host": slot["host"], "url": slot["url"],
                    "categories": sorted(slot["categories"])})
    return out


def build_argv(url, mode, agent_path):
    """The exact command used to run pentest-agent against one target."""
    return ["python3", agent_path, url, "--mode", mode]
