#!/usr/bin/env bash
# Install pentest-agent (multi-module) system-wide.
#
# The tool is now several modules that import each other by name, so you can't
# just copy one file to /usr/local/bin anymore. This installs all modules into
# a library dir and drops a small launcher on your PATH.
set -e

SRC="$(cd "$(dirname "$0")" && pwd)"
LIBDIR="${LIBDIR:-/opt/pentest-agent}"
BIN="${BIN:-/usr/local/bin/pentest-agent}"

# Top-level modules; the WordPress logic now lives in the `wp/` package,
# which is copied wholesale below so every submodule ships (authshell, sqli,
# credattack, privesc, ... — the old flat list silently omitted several).
MODULES="pentest-agent.py http_client.py learn.py"

echo "[*] Installing modules to $LIBDIR"
sudo mkdir -p "$LIBDIR/wp"
for m in $MODULES; do sudo cp "$SRC/$m" "$LIBDIR/"; done
sudo cp "$SRC"/wp/*.py "$LIBDIR/wp/"

echo "[*] Writing launcher to $BIN"
sudo tee "$BIN" >/dev/null <<EOF
#!/usr/bin/env bash
# launcher — runs pentest-agent from its module dir so sibling imports resolve
exec python3 "$LIBDIR/pentest-agent.py" "\$@"
EOF
sudo chmod +x "$BIN"

echo "[+] Installed. Try:  pentest-agent --version"
