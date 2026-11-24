"""Bridge: hand the operator's OWN scan-surfaced hosts to pentest-agent.

Only ever operates on your_hits (the --mine cross-referenced pile). The raw
internet harvest is never touched here. pentest-agent v0.11.0 returns exit 0
regardless of outcome, so success is read from stdout markers, not the rc.
"""
import json
import os
import select
import subprocess
import time


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


def _stream_runner(argv, capture_output=True, text=True, timeout=600):
    """Default production runner: stream the child's output live (so a long
    per-host pentest-agent run is visible, not a silent wait) while ALSO
    capturing it for verdict parsing. Signature mirrors subprocess.run so tests
    swap in a fake. Raises TimeoutExpired to match run_exploitation's handling."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    lines = []
    deadline = time.monotonic() + (timeout or 0)
    try:
        while proc.poll() is None:
            if timeout and time.monotonic() > deadline:
                proc.kill()
                raise subprocess.TimeoutExpired(argv, timeout)
            ready, _, _ = select.select([proc.stdout], [], [], 1.0)
            if ready:
                line = proc.stdout.readline()
                if line:
                    lines.append(line)
                    print("        " + line.rstrip())
        for line in proc.stdout:            # drain whatever's buffered
            lines.append(line)
            print("        " + line.rstrip())
    finally:
        if proc.poll() is None:
            proc.kill()
    return subprocess.CompletedProcess(argv, proc.returncode or 0, "".join(lines))


def run_exploitation(your_hits, *, mode="auto", agent_path="./pentest-agent.py",
                     timeout=600, dry_run=False, runner=_stream_runner,
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
    total = len(targets)
    for i, t in enumerate(targets, 1):
        argv = build_argv(t["url"], mode, agent_path)
        base = {"host": t["host"], "url": t["url"], "categories": t["categories"]}
        log(f"[EXPLOIT] ▶ ({i}/{total}) {t['url']} — pentest-agent (≤{timeout}s):")
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
