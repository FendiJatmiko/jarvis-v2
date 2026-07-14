#!/usr/bin/env bash
# Install pentest-agent (multi-module) system-wide, into its own virtualenv.
#
# The tool is several modules that import each other by name, so you can't just
# copy one file to /usr/local/bin. This copies all modules into a library dir,
# builds an ISOLATED venv there with the Python dependencies, and drops a small
# launcher on your PATH that runs the tool with that venv's interpreter.
#
# Why the venv: pentest-agent imports `requests` (which pulls in urllib3, certifi,
# idna, charset-normalizer). A stock system Python usually lacks these, and modern
# distros block `pip install` into system Python (PEP 668). Without a venv the tool
# dies at `import requests` with ModuleNotFoundError. The venv makes that
# impossible — the launcher always runs the interpreter that has the deps.
#
# Overrides:  LIBDIR=/opt/pentest-agent  BIN=/usr/local/bin/pentest-agent
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
LIBDIR="${LIBDIR:-/opt/pentest-agent}"
BIN="${BIN:-/usr/local/bin/pentest-agent}"
MANDIR="${MANDIR:-/usr/local/share/man/man1}"
VENV="$LIBDIR/venv"
REQ="$SRC/requirements.txt"
MAN="$SRC/pentest-agent.1"

# Top-level modules; the WordPress logic lives in the `wp/` package, copied
# wholesale below so every submodule ships (authshell, sqli, credattack,
# privesc, ... — the old flat list silently omitted several).
MODULES="pentest-agent.py http_client.py learn.py"

echo "── Installing pentest-agent (system-wide) ──────────────────────────"

echo "==> [1/5] Checking prerequisites"
command -v python3 >/dev/null || { echo "    ERROR: python3 not found"; exit 1; }
echo "    found $(python3 --version 2>&1) at $(command -v python3)"
python3 -c 'import venv' 2>/dev/null || {
  echo "    ERROR: the venv module is missing — try: sudo apt install python3-venv"; exit 1; }
[ -f "$REQ" ] || { echo "    ERROR: requirements.txt not found next to install.sh"; exit 1; }

echo "==> [2/5] Copying modules to $LIBDIR"
sudo mkdir -p "$LIBDIR/wp"
for m in $MODULES; do sudo cp "$SRC/$m" "$LIBDIR/"; echo "    + $m"; done
sudo cp "$SRC"/wp/*.py "$LIBDIR/wp/"
echo "    + wp/ ($(ls "$SRC"/wp/*.py | wc -l | tr -d ' ') modules)"
sudo cp "$REQ" "$LIBDIR/"

echo "==> [3/5] Building virtualenv at $VENV"
if [ -d "$VENV" ]; then
  echo "    reusing existing venv"
else
  echo "    creating venv (python3 -m venv)…"
  sudo python3 -m venv "$VENV" || {
    echo "    ERROR: venv creation failed — try: sudo apt install python3-venv"; exit 1; }
  echo "    venv created"
fi
echo "    - upgrading pip"
sudo "$VENV/bin/python" -m pip install --upgrade pip
echo "    - installing dependencies from requirements.txt"
sudo "$VENV/bin/python" -m pip install -r "$LIBDIR/requirements.txt"
echo "    dependencies present in venv:"
sudo "$VENV/bin/python" -m pip list 2>/dev/null \
  | grep -iE '^(requests|urllib3|certifi|idna|charset-normalizer) ' | sed 's/^/      /'

echo "==> [4/5] Writing launcher to $BIN"
sudo mkdir -p "$(dirname "$BIN")"
sudo tee "$BIN" >/dev/null <<EOF
#!/usr/bin/env bash
# launcher — runs pentest-agent from its module dir with the venv interpreter,
# so sibling imports (http_client, learn, wp/) and the deps both resolve.
exec "$VENV/bin/python" "$LIBDIR/pentest-agent.py" "\$@"
EOF
sudo chmod +x "$BIN"
echo "    launcher -> $BIN"
echo "    will run  -> (venv python) $LIBDIR/pentest-agent.py"

echo "==> [5/5] Installing man page"
if [ -f "$MAN" ]; then
  sudo mkdir -p "$MANDIR"
  sudo cp "$MAN" "$MANDIR/pentest-agent.1"
  echo "    man page -> $MANDIR/pentest-agent.1"
  command -v mandb >/dev/null 2>&1 && sudo mandb -q >/dev/null 2>&1 || true
  echo "    try: man pentest-agent"
else
  echo "    (pentest-agent.1 not found next to install.sh — skipping)"
fi

echo ""
echo "  ✓ Installed. Try:  pentest-agent --version   or   man pentest-agent"
