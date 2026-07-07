#!/usr/bin/env python3
"""
recon.py — multi-technique port discovery for cloud/firewalled targets

Runs nmap evasion techniques in parallel phases, escalating when a phase
finds nothing. Designed for targets behind cloud firewalls (AWS, GCP, Azure,
Cloudflare) where a plain nmap returns 0 open ports.

Phase 1  Fast baseline   no root, parallel   standard + wider range + HTTP probe
Phase 2  Stealth         no root, parallel   slow timing + data camouflage + randomize
Phase 2R Raw socket      root only, parallel SYN + source-port + fragment + FIN/NULL/Xmas + ACK + decoy
Phase 3  Last resort     sequential          paranoid timing + masscan + rustscan

Usage:
  python3 recon.py <target>
  python3 recon.py <target> --full             run all phases even if ports found
  python3 recon.py <target> --phase 1          only phase 1
  python3 recon.py <target> --out result.json  save results
  python3 recon.py <target> --ports 1-65535    full port range (slow)
  python3 recon.py <target> --trio             nmap + masscan + rustscan in parallel
"""
__version__ = "1.1.0"

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Terminal colours (no deps)
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

def _cyan(t):   return _c("36", t)
def _green(t):  return _c("32;1", t)
def _yellow(t): return _c("33", t)
def _red(t):    return _c("31", t)
def _dim(t):    return _c("2", t)
def _bold(t):   return _c("1", t)

# ---------------------------------------------------------------------------
# Shared results collector
# ---------------------------------------------------------------------------

class ReconResults:
    def __init__(self):
        self._ports: dict = {}          # (port, proto) → dict
        self._waf: list   = []
        self._os:  str    = ""
        self._ssl: dict   = {}
        self._lock = threading.Lock()

    def add_ports(self, ports: list, source: str):
        with self._lock:
            new = 0
            for p in ports:
                key = (p["port"], p["proto"])
                if key not in self._ports:
                    self._ports[key] = {**p, "sources": [source]}
                    new += 1
                else:
                    existing = self._ports[key]
                    # Prefer richer version string (longer = more detail from -sV)
                    if len(p.get("version", "")) > len(existing.get("version", "")):
                        existing["version"] = p["version"]
                    # Keep the more specific service name (e.g. ssl/https over https)
                    if "/" in p.get("service", "") and "/" not in existing.get("service", ""):
                        existing["service"] = p["service"]
                    srcs = existing["sources"]
                    if source not in srcs:
                        srcs.append(source)
            return new

    def set_waf(self, waf: list):
        with self._lock:
            self._waf = waf

    def set_os(self, os_str: str):
        with self._lock:
            if os_str:
                self._os = os_str

    def set_ssl(self, info: dict):
        with self._lock:
            self._ssl = info

    @property
    def all_ports(self) -> list:
        return sorted(self._ports.values(), key=lambda p: p["port"])

    @property
    def count(self) -> int:
        return len(self._ports)

    def to_dict(self) -> dict:
        return {
            "ports": self.all_ports,
            "waf":   self._waf,
            "os":    self._os,
            "ssl":   self._ssl,
        }

# ---------------------------------------------------------------------------
# Execution helpers
# ---------------------------------------------------------------------------

def _run(cmd: str, timeout: int = 360) -> str:
    """Run a shell command, return combined stdout+stderr."""
    try:
        r = subprocess.run(
            ["bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""

def _has_tool(name: str) -> bool:
    return subprocess.run(["which", name], capture_output=True).returncode == 0

def _can_raw_socket() -> bool:
    """True if nmap can send raw packets (root or CAP_NET_RAW)."""
    if os.geteuid() == 0:
        return True
    r = subprocess.run(
        ["nmap", "-sS", "-p", "1", "127.0.0.1"],
        capture_output=True, text=True,
    )
    return "requires root" not in r.stderr.lower()

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_nmap(output: str) -> list:
    ports = []
    for line in output.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
        if m:
            ports.append({
                "port":    int(m.group(1)),
                "proto":   m.group(2),
                "service": m.group(3),
                "version": m.group(4).strip(),
            })
    return ports

def _parse_nmap_ack(output: str) -> list:
    """ACK scan returns 'unfiltered' not 'open' — maps which ports have no FW rule."""
    ports = []
    for line in output.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+unfiltered\s+(\S+)", line)
        if m:
            ports.append({
                "port":    int(m.group(1)),
                "proto":   m.group(2),
                "service": m.group(3),
                "version": "(ACK-unfiltered — no firewall rule; may or may not be open)",
            })
    return ports

def _parse_masscan(output: str) -> list:
    ports = []
    for line in output.splitlines():
        m = re.match(r"Discovered open port (\d+)/(tcp|udp) on", line)
        if m:
            ports.append({
                "port": int(m.group(1)), "proto": m.group(2),
                "service": "unknown", "version": "",
            })
    return ports

def _parse_curl_http(host: str, port: int, scheme: str) -> dict | None:
    """Return port dict if host responds to HTTP on that port."""
    url = f"{scheme}://{host}:{port}"
    out = _run(f"curl -sI -k --connect-timeout 5 --max-time 10 {url} 2>&1 | head -8")
    if not re.search(r"HTTP/[12]", out):
        return None
    server = ""
    m = re.search(r"[Ss]erver:\s*(.+)", out)
    if m:
        server = m.group(1).strip()
    svc = "https" if scheme == "https" else "http"
    return {"port": port, "proto": "tcp", "service": svc, "version": server}

def _parse_ssl_cert(host: str, port: int = 443) -> dict:
    """Extract SSL cert info via nmap ssl-cert script (more reliable than openssl s_client)."""
    out = _run(
        f"nmap -Pn -sT -p {port} --script ssl-cert {host} 2>&1", timeout=30
    )
    if "ssl-cert" not in out:
        return {}
    info: dict = {}
    for line in out.splitlines():
        line = line.strip()
        if "Subject:" in line:
            info["subject"] = line.split("Subject:", 1)[1].strip()
        elif "Issuer:" in line:
            info["issuer"] = line.split("Issuer:", 1)[1].strip()
        elif "Not valid after" in line:
            info["expires"] = line.split(":", 1)[1].strip()
        elif "DNS:" in line or "commonName=" in line:
            sans = re.findall(r"DNS:([^\s,]+)", line)
            if sans:
                info.setdefault("san", []).extend(sans)
    return info

_WAF_SIGS = {
    "Cloudflare":  [r"CF-Ray", r"server:\s*cloudflare"],
    "Sucuri":      [r"X-Sucuri-ID", r"x-sucuri-cache"],
    "Akamai":      [r"AkamaiGHost", r"X-Check-Cacheable"],
    "CloudFront":  [r"X-Amz-Cf-Id", r"Via:.*CloudFront"],
    "Fastly":      [r"X-Fastly-Request-ID"],
    "Incapsula":   [r"X-Iinfo", r"incap_ses"],
    "Imperva":     [r"X-CDN:\s*Imperva"],
    "Azure CDN":   [r"X-MSEdge-Ref", r"x-azure-ref"],
    "F5 BigIP":    [r"X-Cnection", r"TS[0-9a-f]{8}"],
}

def _detect_waf(host: str) -> list:
    headers = _run(f"curl -sI -k --connect-timeout 5 --max-time 10 https://{host} 2>&1")
    if not headers:
        headers = _run(f"curl -sI --connect-timeout 5 --max-time 10 http://{host} 2>&1")
    found = []
    for name, pats in _WAF_SIGS.items():
        if any(re.search(p, headers, re.I) for p in pats):
            found.append(name)
    return found

def _guess_os(host: str) -> str:
    """Guess OS from ICMP TTL; fall back to nmap TCP fingerprint if ICMP blocked."""
    # Try ping first (fastest)
    out = _run(f"ping -c 1 -W 3 {host} 2>&1")
    m = re.search(r"ttl=(\d+)", out, re.I)
    if m:
        ttl = int(m.group(1))
        if ttl <= 64:
            return f"Linux/Unix (TTL={ttl})"
        if ttl <= 128:
            return f"Windows (TTL={ttl})"
        return f"Network device (TTL={ttl})"
    # ICMP blocked — check nmap's TCP fingerprint clues from banner
    out2 = _run(f"nmap -Pn -sT -p 22,80,3389 --script banner {host} 2>&1", timeout=30)
    if "ubuntu" in out2.lower() or "debian" in out2.lower():
        return "Linux/Ubuntu (SSH banner)"
    if "windows" in out2.lower() or "microsoft" in out2.lower():
        return "Windows (banner/RDP)"
    if "openssh" in out2.lower():
        return "Linux/Unix (OpenSSH banner)"
    return ""

# ---------------------------------------------------------------------------
# Technique definitions
# ---------------------------------------------------------------------------
# Each technique is a dict:
#   name        display name
#   cmd         bash command (use {host} and {ports} placeholders)
#   parse       "nmap" | "nmap_ack" | "masscan" | "http"
#   phase       1 | 2 | 3
#   root        True = requires raw socket
#   tool        external tool name to check (optional)
#   timeout     seconds (default 300)
#   note        shown after results

HTTP_PROBE_PORTS = [
    (80,   "http",  "http"),
    (443,  "https", "https"),
    (8080, "http",  "http-alt"),
    (8443, "https", "https-alt"),
    (8000, "http",  "http-alt"),
    (8888, "http",  "http-alt"),
    (3000, "http",  "http-dev"),
    (5000, "http",  "http-dev"),
    (9000, "http",  "http-dev"),
]


def _build_techniques(port_arg: str) -> list:
    p = port_arg  # e.g. "--top-ports 200" or "-p 1-65535"
    return [
        # ── Phase 1: Fast, no root ───────────────────────────────────────
        {
            "name": "connect-scan",
            "cmd":  f"nmap -Pn -sT -sV -sC {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 1, "root": False,
            "note": "TCP connect (-sT), service/version detection",
        },
        {
            "name": "wide-range",
            "cmd":  f"nmap -Pn -sT -T3 {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 1, "root": False,
            "note": "TCP connect, wider top-ports sweep",
        },
        {
            "name": "http-probe",
            "cmd":  "",   # handled specially via _probe_http
            "parse": "http", "phase": 1, "root": False,
            "note": "direct curl probe on common web ports",
        },

        # ── Phase 2: Stealth, no root ────────────────────────────────────
        {
            "name": "slow-T2",
            "cmd":  f"nmap -Pn -sT -T2 {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 2, "root": False,
            "timeout": 600,
            "note": "polite timing — avoids rate-limit triggers",
        },
        {
            "name": "data-camouflage",
            "cmd":  f"nmap -Pn -sT --data-length 64 {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 2, "root": False,
            "note": "appends 64 random bytes — confuses some DPI signatures",
        },
        {
            "name": "randomize",
            "cmd":  f"nmap -Pn -sT --randomize-hosts {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 2, "root": False,
            "note": "randomise probe order — defeats sequential-port detection",
        },

        # ── Phase 2R: Raw socket (root) ───────────────────────────────────
        {
            "name": "syn-scan",
            "cmd":  f"nmap -Pn -sS -T3 {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 2, "root": True,
            "note": "SYN/half-open — doesn't complete handshake, harder to log",
        },
        {
            "name": "src-port-53",
            "cmd":  f"nmap -Pn -sS -g 53 {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 2, "root": True,
            "note": "packets appear to originate from port 53 (DNS) — bypasses some cloud ACLs",
        },
        {
            "name": "src-port-80",
            "cmd":  f"nmap -Pn -sS -g 80 {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 2, "root": True,
            "note": "packets appear to originate from port 80 — bypasses some HTTP-aware FWs",
        },
        {
            "name": "fragment",
            "cmd":  f"nmap -Pn -f --data-length 64 -sS {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 2, "root": True,
            "note": "splits TCP headers across multiple IP fragments — evades stateless DPI",
        },
        {
            "name": "fin-scan",
            "cmd":  f"nmap -Pn -sF -T2 {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 2, "root": True,
            "note": "FIN flag only — bypasses stateless filters that only block SYN",
        },
        {
            "name": "null-scan",
            "cmd":  f"nmap -Pn -sN -T2 {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 2, "root": True,
            "note": "no flags set — bypasses some stateless packet filters",
        },
        {
            "name": "xmas-scan",
            "cmd":  f"nmap -Pn -sX -T2 {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 2, "root": True,
            "note": "FIN+PSH+URG flags — bypasses some stateless filters",
        },
        {
            "name": "ack-map",
            "cmd":  f"nmap -Pn -sA -T3 {p} {{host}} 2>&1",
            "parse": "nmap_ack", "phase": 2, "root": True,
            "note": "maps firewall rules (unfiltered = no ACL rule, not necessarily open)",
        },
        {
            "name": "decoy",
            "cmd":  f"nmap -Pn -D RND:5,ME -sS {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 2, "root": True,
            "note": "spoofs 5 random source IPs alongside yours — hides real scanner",
        },

        # ── Phase 1 additions: masscan + rustscan (when available) ──────────
        # Run alongside nmap in phase 1 — not last resort, complementary tools.
        # masscan covers the full 1-65535 range nmap's --top-ports misses.
        # rustscan does async connect discovery then hands open ports to nmap.
        {
            "name": "masscan",
            "cmd":  "masscan -p1-65535 --rate 500 {host} 2>&1",
            "parse": "masscan", "phase": 1, "root": True,
            "tool": "masscan",
            "timeout": 180,
            "note": "full 1-65535, raw SYN flood @ 500 pps — needs root",
        },
        {
            "name": "rustscan",
            "cmd":  "rustscan -a {host} --range 1-65535 --ulimit 5000 -- -sV 2>&1",
            "parse": "nmap", "phase": 1, "root": False,
            "tool": "rustscan",
            "timeout": 600,
            "note": "async connect 1-65535 → nmap service detection on open ports",
        },

        # ── Phase 3: Slow / last resort ──────────────────────────────────
        {
            "name": "paranoid-T1",
            "cmd":  f"nmap -Pn -sT -T1 --scan-delay 3s --max-retries 2 {p} {{host}} 2>&1",
            "parse": "nmap", "phase": 3, "root": False,
            "timeout": 1800,
            "note": "slowest nmap timing — 3 s between probes — evades rate-limit FWs",
        },
    ]

# ---------------------------------------------------------------------------
# Run a single technique
# ---------------------------------------------------------------------------

_print_lock = threading.Lock()

def _tprint(msg: str):
    with _print_lock:
        print(msg, flush=True)

def _run_technique(tech: dict, host: str, results: ReconResults) -> tuple:
    """Execute one technique. Returns (name, new_port_count, elapsed)."""
    name = tech["name"]
    t0   = time.monotonic()

    if tech["parse"] == "http":
        ports = []
        for port, scheme, svc in HTTP_PROBE_PORTS:
            p = _parse_curl_http(host, port, scheme)
            if p:
                ports.append(p)
    else:
        cmd = tech["cmd"].format(host=host)
        out = _run(cmd, timeout=tech.get("timeout", 360))
        if tech["parse"] == "nmap":
            ports = _parse_nmap(out)
        elif tech["parse"] == "nmap_ack":
            ports = _parse_nmap_ack(out)
        elif tech["parse"] == "masscan":
            ports = _parse_masscan(out)
        else:
            ports = []

    new  = results.add_ports(ports, name)
    secs = time.monotonic() - t0
    return (name, new, secs, ports)

# ---------------------------------------------------------------------------
# Trio runner — nmap + masscan + rustscan in parallel
# ---------------------------------------------------------------------------

def _run_trio(host: str, nmap_ports: str, results: ReconResults, can_raw: bool) -> None:
    """
    Run nmap, masscan, and rustscan simultaneously, then do a follow-up
    targeted nmap -sV pass on any ports masscan found without version info.

    masscan is the fastest full-range scanner (raw SYN, 1000 pps) but has
    no service detection. nmap covers --top-ports with version detection.
    rustscan does async connect on all 65535 ports then calls nmap -sV on
    the open ones. Together they cover speed, range, and depth.
    """
    techs   = []
    skipped = []

    # ── nmap: always available ─────────────────────────────────────
    techs.append({
        "name":    "nmap",
        "cmd":     f"nmap -Pn -sT -sV -sC {nmap_ports} {{host}} 2>&1",
        "parse":   "nmap",
        "timeout": 360,
        "note":    f"TCP connect + version/script detection  ({nmap_ports})",
    })

    # ── masscan: raw SYN, needs root + binary ─────────────────────
    if _has_tool("masscan") and can_raw:
        techs.append({
            "name":    "masscan",
            "cmd":     "masscan -p1-65535 --rate 1000 {host} 2>&1",
            "parse":   "masscan",
            "timeout": 300,
            "note":    "full 1-65535, raw SYN packets @ 1000 pps",
        })
    else:
        parts = []
        if not _has_tool("masscan"):
            parts.append("not installed — sudo apt install masscan")
        elif not can_raw:
            parts.append("needs root — sudo python3 recon.py ... --trio")
        skipped.append(("masscan", "  ·  ".join(parts)))

    # ── rustscan: async connect, no root needed ────────────────────
    if _has_tool("rustscan"):
        techs.append({
            "name":    "rustscan",
            "cmd":     "rustscan -a {host} --range 1-65535 --ulimit 5000 -- -sV 2>&1",
            "parse":   "nmap",
            "timeout": 600,
            "note":    "async connect 1-65535  →  nmap -sV on open ports",
        })
    else:
        skipped.append(("rustscan", "not installed — cargo install rustscan"))

    if skipped:
        _tprint("")
        for name, reason in skipped:
            _tprint(f"  {_yellow('skip')}  {_bold(name)}: {_dim(reason)}")

    _run_phase(techs, host, results, "TRIO — nmap · masscan · rustscan")

    # ── follow-up: targeted -sV on masscan-only ports ─────────────
    # masscan finds ports fast but returns no service/version info.
    # Any port flagged only by masscan (version still empty) gets a
    # dedicated nmap -sV run so the final report has full service details.
    masscan_unversioned = [
        p for p in results.all_ports
        if "masscan" in p.get("sources", []) and not p.get("version")
    ]
    if masscan_unversioned:
        port_list = ",".join(str(p["port"]) for p in masscan_unversioned)
        _tprint(f"\n  {_cyan('→')}  masscan found {len(masscan_unversioned)} port(s) without service info")
        _tprint(f"  {_cyan('→')}  targeted nmap -sV on: {port_list}")
        svc_tech = {
            "name":    "nmap-svc",
            "cmd":     f"nmap -Pn -sT -sV -p {port_list} {{host}} 2>&1",
            "parse":   "nmap",
            "timeout": 120,
            "note":    "service detection on masscan-discovered ports",
        }
        _run_phase([svc_tech], host, results, "Service detection (masscan ports)")


# ---------------------------------------------------------------------------
# Phase runner
# ---------------------------------------------------------------------------

def _run_phase(techs: list, host: str, results: ReconResults,
               label: str, max_workers: int = 6) -> int:
    """Run all techniques in a phase concurrently. Returns total new ports found."""
    if not techs:
        return 0

    _tprint(f"\n{_bold(_cyan(f'── {label} ──'))}")
    for t in techs:
        _tprint(f"  {_dim('queued')}  {_bold(t['name'])}  {_dim(t['note'])}")
    _tprint("")

    total_new = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_run_technique, t, host, results): t for t in techs}
        for fut in as_completed(futures):
            tech = futures[fut]
            try:
                name, new, secs, ports = fut.result()
            except Exception as e:
                _tprint(f"  {_red('ERR')}  {tech['name']}: {e}")
                continue

            total_new += new
            elapsed = f"{secs:.0f}s"
            if ports:
                found_str = ", ".join(f"{p['port']}/{p['service']}" for p in ports)
                _tprint(f"  {_green('HIT')}  {_bold(name)} ({elapsed}): "
                        f"{_green(found_str)}")
            else:
                _tprint(f"  {_dim('nil')}  {name} ({elapsed}): no open ports")

    return total_new

# ---------------------------------------------------------------------------
# Fingerprinting helpers (run in background threads)
# ---------------------------------------------------------------------------

def _fingerprint(host: str, results: ReconResults):
    """Run WAF, OS, and SSL fingerprinting concurrently."""
    def _do_waf():
        waf = _detect_waf(host)
        if waf:
            results.set_waf(waf)

    def _do_os():
        os_str = _guess_os(host)
        if os_str:
            results.set_os(os_str)

    def _do_ssl():
        # Try 443 or first https port found
        https_ports = [p["port"] for p in results.all_ports
                       if p["service"] in ("https", "ssl/https", "https-alt")]
        port = https_ports[0] if https_ports else 443
        ssl = _parse_ssl_cert(host, port)
        if ssl:
            results.set_ssl(ssl)

    threads = [
        threading.Thread(target=_do_waf, daemon=True),
        threading.Thread(target=_do_os,  daemon=True),
        threading.Thread(target=_do_ssl, daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def _print_summary(host: str, results: ReconResults, elapsed: float):
    print(f"\n{'═'*60}")
    print(_bold(f"  RECON SUMMARY — {host}  ({elapsed:.0f}s total)"))
    print(f"{'═'*60}")

    ports = results.all_ports
    if not ports:
        print(_red("  No open ports found across all techniques."))
        print("  → Try: sudo recon.py (enables raw-socket techniques)")
        print("  → Try: recon.py --phase 3 (paranoid timing / masscan)")
    else:
        print(f"\n  {_green(f'{len(ports)} open port(s):')} \n")
        for p in ports:
            srcs   = ", ".join(p.get("sources", []))
            ver    = f"  {_dim(p['version'])}" if p.get("version") else ""
            print(f"    {_bold(str(p['port'])):>6}/{p['proto']}  "
                  f"{_cyan(p['service']):<16}{ver}")
            print(f"{'':>28}{_dim(f'found by: {srcs}')}")

    r = results.to_dict()
    if r["os"]:
        print(f"\n  OS guess  : {_yellow(r['os'])}")
    if r["waf"]:
        print(f"  WAF/CDN   : {_yellow(', '.join(r['waf']))}")
    if r["ssl"]:
        ssl = r["ssl"]
        print(f"  SSL cert  : {ssl.get('subject', '')}")
        if "san" in ssl:
            print(f"  SANs      : {', '.join(ssl['san'][:8])}")
        print(f"  Expires   : {ssl.get('expires', '')}")

    print(f"\n{'═'*60}\n")

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Multi-technique port discovery for firewalled targets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--version", action="version", version=f"recon {__version__}")
    parser.add_argument("target", help="IP, hostname, or CIDR")
    parser.add_argument("--full", action="store_true",
                        help="run all phases even if ports are found early")
    parser.add_argument("--phase", type=int, choices=[1, 2, 3],
                        help="run only this phase number")
    parser.add_argument("--ports", default="--top-ports 200",
                        help="nmap port spec (default: --top-ports 200)")
    parser.add_argument("--trio", action="store_true",
                        help="run nmap + masscan + rustscan in parallel, then merge results")
    parser.add_argument("--out", metavar="FILE",
                        help="write JSON results to FILE")
    args = parser.parse_args()

    host    = args.target
    CAN_RAW = _can_raw_socket()

    print(f"\n{_bold('recon.py')} {__version__}  target: {_cyan(host)}")
    print(f"  root/raw-socket : {_green('yes') if CAN_RAW else _yellow('no (root techniques skipped)')}")
    print(f"  masscan         : {_green('yes') if _has_tool('masscan') else _dim('not found')}")
    print(f"  rustscan        : {_green('yes') if _has_tool('rustscan') else _dim('not found')}")
    print(f"  port spec       : {args.ports}")
    if args.trio:
        print(f"  mode            : {_cyan('TRIO')} (nmap + masscan + rustscan parallel)")

    all_techniques = _build_techniques(args.ports)
    results = ReconResults()
    t_start = time.monotonic()

    # Filter out techniques we can't run
    def _eligible(t: dict) -> bool:
        if t.get("root") and not CAN_RAW:
            return False
        if t.get("tool") and not _has_tool(t["tool"]):
            return False
        return True

    def _phase_techs(phase_num: int) -> list:
        return [t for t in all_techniques
                if t["phase"] == phase_num and _eligible(t)]

    # ── TRIO mode — nmap + masscan + rustscan in parallel ────────────────
    if args.trio:
        _tprint(f"\n{_bold(_cyan('── TRIO MODE ──'))}")
        _tprint(f"  nmap ({args.ports}) + masscan (1-65535 @ 1000pps) + rustscan (1-65535)")
        _run_trio(host, args.ports, results, CAN_RAW)

    # ── Normal phase logic (skipped in --trio mode) ───────────────────
    else:
        # ── Phase 1 ──────────────────────────────────────────────────────
        if args.phase in (None, 1):
            p1 = _phase_techs(1)
            new = _run_phase(p1, host, results, "PHASE 1 — Fast baseline (parallel)")
            if new and not args.full and args.phase is None:
                _tprint(_green(f"\n  Phase 1 found {results.count} port(s) — "
                               "skipping deeper phases (use --full to run anyway)"))

        # ── Phase 2 ──────────────────────────────────────────────────────
        run_p2 = (args.phase in (None, 2) and
                  (args.full or results.count == 0 or args.phase == 2))
        if run_p2:
            p2 = _phase_techs(2)
            if not p2:
                _tprint(_yellow("\n  Phase 2 requires root — skipping "
                                "(run with sudo to enable SYN/FIN/fragment/decoy scans)"))
            else:
                run = _run_phase(p2, host, results, "PHASE 2 — Stealth (parallel)")
                if run and not args.full and args.phase is None:
                    _tprint(_green(f"\n  Phase 2 found ports — skipping Phase 3"))

        # ── Phase 3 ──────────────────────────────────────────────────────
        run_p3 = (args.phase in (None, 3) and
                  (args.full or results.count == 0 or args.phase == 3))
        if run_p3:
            p3 = _phase_techs(3)
            if p3:
                _tprint(f"\n{_bold(_cyan('── PHASE 3 — Last resort (sequential) ──'))}")
                for t in p3:
                    _tprint(f"\n  {_bold(t['name'])} — {_dim(t['note'])}")
                    _, new, secs, ports = _run_technique(t, host, results)
                    elapsed = f"{secs:.0f}s"
                    if ports:
                        found_str = ", ".join(f"{p['port']}/{p['service']}" for p in ports)
                        _tprint(f"  {_green('HIT')} ({elapsed}): {_green(found_str)}")
                        if not args.full:
                            _tprint("  Found ports — stopping Phase 3 early")
                            break
                    else:
                        _tprint(f"  {_dim('nil')} ({elapsed}): no open ports")

    # ── Fingerprinting (WAF / OS / SSL) — always ─────────────────────
    _tprint(f"\n{_bold(_cyan('── Fingerprinting (WAF / OS / SSL) ──'))}")
    _fingerprint(host, results)
    r = results.to_dict()
    if r["os"]:
        _tprint(f"  OS guess  : {_yellow(r['os'])}")
    if r["waf"]:
        _tprint(f"  WAF/CDN   : {_yellow(', '.join(r['waf']))}")
    if r["ssl"]:
        _tprint(f"  SSL cert  : {r['ssl'].get('subject', '')}")
        sans = r["ssl"].get("san", [])
        if sans:
            _tprint(f"  SANs      : {', '.join(sans[:8])}")

    # ── Summary ─────────────────────────────────────────────────────────
    _print_summary(host, results, time.monotonic() - t_start)

    # ── JSON output ─────────────────────────────────────────────────────
    if args.out:
        with open(args.out, "w") as f:
            json.dump(results.to_dict(), f, indent=2)
        _tprint(f"  Results saved to {args.out}")


if __name__ == "__main__":
    main()
