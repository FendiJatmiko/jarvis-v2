# Webshell pipeline — manual smoke test

Ground-truth target: server-IOM WordPress lab (File Manager 6.0, CVE-2020-25213).

1. Ensure the lab is reachable from where pentest-agent runs (LAN or tunnel).
2. Run: `pentest-agent http://<lab-host> --no-cleanup`
3. Expect:
   - `[FINGERPRINT] wordpress=True ... plugins=['wp-file-manager']`
   - `[MATCH] 1 candidate(s): ['CVE-2020-25213']`
   - `[VERIFY] ✅ WEBSHELL CONFIRMED via 'wsh_<token>.php'`  with `id → uid=33(www-data)`
4. Re-run without `--no-cleanup`; confirm `cleanup: removed`.

If VERIFY fails while FINGERPRINT/MATCH succeed, the bug is in exploit/verify,
not the target — the target is known-good.
