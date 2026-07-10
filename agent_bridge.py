"""Bridge: hand the operator's OWN scan-surfaced hosts to pentest-agent.

Only ever operates on your_hits (the --mine cross-referenced pile). The raw
internet harvest is never touched here. pentest-agent v0.11.0 returns exit 0
regardless of outcome, so success is read from stdout markers, not the rc.
"""
import json
import os
import subprocess


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


_SHELL_MARKERS = ("WEBSHELL CONFIRMED", "WEBSHELL via")


def parse_verdict(stdout, rc):
    """pentest-agent always exits 0; a confirmed shell is only visible as a
    stdout marker. rc != 0 therefore means the process itself broke."""
    text = stdout or ""
    if any(m in text for m in _SHELL_MARKERS):
        return "shell"
    if rc != 0:
        return "error"
    return "clean"


def run_exploitation(your_hits, *, mode="auto", agent_path="./pentest-agent.py",
                     timeout=600, dry_run=False, runner=subprocess.run,
                     log=print):
    """Fan out sequentially over the operator's OWN surfaced hosts. Never
    touches the harvested pile. One host failing never aborts the sweep."""
    targets = dedupe_targets(your_hits)
    if not targets:
        log("[EXPLOIT] no owned hosts surfaced — nothing to hand to pentest-agent")
        return []

    log(f"[EXPLOIT] {len(targets)} owned host(s) -> pentest-agent (mode={mode}):")
    for t in targets:
        log(f"    - {t['url']}  [{', '.join(t['categories'])}]")

    if dry_run:
        log("[EXPLOIT] --exploit-dry-run: listed targets, running nothing")
        return [{"host": t["host"], "url": t["url"],
                 "categories": t["categories"], "verdict": "dry-run"}
                for t in targets]

    results = []
    for t in targets:
        argv = build_argv(t["url"], mode, agent_path)
        base = {"host": t["host"], "url": t["url"], "categories": t["categories"]}
        try:
            cp = runner(argv, capture_output=True, text=True, timeout=timeout)
            stdout = cp.stdout or ""
            rc = cp.returncode
            tail = "\n".join(stdout.splitlines()[-20:])
            results.append({**base, "rc": rc,
                            "verdict": parse_verdict(stdout, rc), "tail": tail})
        except subprocess.TimeoutExpired:
            log(f"    [!] {t['url']} timed out after {timeout}s")
            results.append({**base, "verdict": "timeout", "error": "timeout"})
        except Exception as e:  # a broken spawn must not sink the sweep
            log(f"    [!] {t['url']} failed: {e}")
            results.append({**base, "verdict": "error", "error": str(e)})
    return results


def write_exploit_report(ts, results, *, report_dir="."):
    """Fold the exploitation pass back into the scan artifacts written by
    scanner_dork.write_report."""
    md_path = os.path.join(report_dir, f"scan-{ts}.md")
    json_path = os.path.join(report_dir, f"scan-{ts}.json")

    with open(md_path, "a") as f:
        f.write("\n## Exploitation pass\n\n")
        if not results:
            f.write("_No owned hosts were handed to pentest-agent._\n")
        for r in results:
            f.write(f"- **{r['url']}** — verdict **{r['verdict']}**"
                    f" (rc={r.get('rc', 'n/a')}) "
                    f"[{', '.join(r.get('categories', []))}]\n")

    with open(json_path) as f:
        data = json.load(f)
    data["exploit_results"] = results
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
