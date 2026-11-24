# pentest-agent — install & run

`pentest-agent` is a WordPress webshell + privilege-escalation assessment tool
for **authorized** targets. It is a multi-module Python app: `pentest-agent.py`
imports `http_client`, `learn`, and the `wp/` package (fingerprint, match,
vulns, recipes, exploit, privesc, credattack, sqli, authshell, verify).

---

## TL;DR

```bash
make -f Makefile.pentest-agent install      # builds an isolated venv + a `pentest-agent` launcher
pentest-agent --version
```

That's it. You do **not** need to activate a virtualenv yourself — see below for
why that matters.

---

## The "not inside a virtualenv" error (read this first)

If you run the script directly with your system Python:

```bash
$ python3 pentest-agent.py --version
Traceback (most recent call last):
  File "pentest-agent.py", line 24, in <module>
    import requests
ModuleNotFoundError: No module named 'requests'
```

**Why:** the tool depends on `requests` (which pulls in `urllib3`, `certifi`,
`idna`, `charset-normalizer`). A stock system Python usually doesn't have these
installed, and on modern distros you often *can't* `pip install` into it anyway
(PEP 668 "externally-managed-environment"). So running the raw script — or the
old `install.sh` launcher that calls system `python3` — blows up the moment it
hits `import requests`.

**The fix is `make -f Makefile.pentest-agent install`.** It does two things that together make the
error impossible:

1. Creates a dedicated virtualenv at `~/.local/share/pentest-agent/venv` and
   installs the dependencies **into that venv** (never touching system Python).
2. Writes a launcher to `~/.local/bin/pentest-agent` that hard-codes the venv's
   Python:

   ```bash
   #!/usr/bin/env bash
   exec "/home/you/.local/share/pentest-agent/venv/bin/python" \
        "/path/to/repo/pentest-agent.py" "$@"
   ```

Because the launcher points straight at the venv interpreter, `pentest-agent`
runs with the right dependencies **from any directory**, and you never have to
`source venv/bin/activate`. The venv is used automatically, invisibly.

---

## Prerequisites

- **Python 3.9+** (developed against 3.12).
- **The venv module *and* pip.** On Debian/Ubuntu these are two separate
  packages — installing only `python3-venv` gets you a venv with no pip
  inside it, which fails later with a confusing `No module named pip`:

  ```bash
  sudo apt install python3-venv python3-pip
  ```

  If either is missing, `make -f Makefile.pentest-agent install` checks for
  this upfront and tells you exactly what to install. If you already hit the
  `No module named pip` error before this check existed, just re-run
  `make -f Makefile.pentest-agent install` — it now detects a pip-less venv
  left over from a previous attempt and rebuilds it automatically.

---

## Install

```bash
make -f Makefile.pentest-agent install
```

You'll see verbose, step-by-step output:

```
── Installing pentest-agent ─────────────────────────────────────────
==> [1/3] Checking prerequisites
    found Python 3.12.3 at /usr/bin/python3
==> [2/3] Preparing virtualenv at ~/.local/share/pentest-agent/venv
    creating venv (python3 -m venv)…
    venv created
==> [3/3] Installing dependencies into the venv
    - upgrading pip
    - installing from requirements.txt
    dependencies present in venv:
      requests   2.34.2
      urllib3    2.7.0
      certifi    ...
==> Writing launcher
    launcher -> ~/.local/bin/pentest-agent
    will run  -> (venv python) /path/to/repo/pentest-agent.py

  ✓ Installed: ~/.local/bin/pentest-agent
    Try:       pentest-agent --version
```

### Make sure `~/.local/bin` is on your PATH

The launcher lands in `~/.local/bin`. If that's not on your `PATH`, the installer
prints a NOTE telling you so. Add it to your shell rc:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc   # or ~/.bashrc
exec $SHELL -l
```

### Custom install location

Override `PREFIX` to install elsewhere (both the venv and launcher move):

```bash
make -f Makefile.pentest-agent install PREFIX=/opt/tools     # venv -> /opt/tools/share/..., launcher -> /opt/tools/bin
```

---

## Verify it works

```bash
make -f Makefile.pentest-agent check    # runs `pentest-agent --version`, prints OK on success
```

or directly, from any directory (proving you don't need a venv shell):

```bash
cd /tmp && pentest-agent --version
# -> pentest-agent.py 0.16.0
```

---

## Manual page

Both installers also install a man page, so you get full documentation offline:

```bash
man pentest-agent
```

- `make -f Makefile.pentest-agent install` puts it at
  `$PREFIX/share/man/man1/pentest-agent.1` (default `~/.local/share/man/man1/`).
- `install.sh` puts it at `/usr/local/share/man/man1/pentest-agent.1`.

Both locations are already on the default `MANPATH` (the per-user one because
`~/.local/bin` is on your `PATH`), so `man pentest-agent` works with no extra
setup. `whatis pentest-agent` and `apropos` work too — the installers run
`mandb` to index it.

Preview the page **without installing** straight from the repo:

```bash
man ./pentest-agent.1
```

The page source is `pentest-agent.1` (roff / section 1); edit it there and
re-run the installer to update the installed copy.

The launcher executes `pentest-agent.py` **in place** — from this repo checkout,
using the venv's interpreter. Two consequences:

- **Edits take effect immediately.** Change `pentest-agent.py` or anything under
  `wp/`, and the next `pentest-agent` run picks it up. No reinstall needed.
- **Don't move or delete the repo.** The launcher holds an absolute path to it.
  If you move the checkout, run `make -f Makefile.pentest-agent reinstall` from
  the new location to rewrite the launcher's paths.

---

## Update / rebuild / uninstall

```bash
make -f Makefile.pentest-agent reinstall    # rewrite the launcher (e.g. after moving the repo)
make -f Makefile.pentest-agent uninstall    # remove the launcher and the venv
```

To pull new Python dependencies after editing `requirements.txt`, just re-run
`make -f Makefile.pentest-agent install` — it reuses the existing venv and
installs any additions.

---

## Manual install (no make)

If you'd rather not use the Makefile, reproduce it by hand:

```bash
python3 -m venv ~/.venvs/pentest-agent
~/.venvs/pentest-agent/bin/pip install -r requirements.txt

# run it (always via the venv python, from the repo root):
~/.venvs/pentest-agent/bin/python pentest-agent.py --version
```

Or activate the venv for an interactive session:

```bash
source ~/.venvs/pentest-agent/bin/activate
python pentest-agent.py --version
deactivate
```

---

## System-wide install (`install.sh`)

For a shared, system-wide install (as opposed to the per-user
`make -f Makefile.pentest-agent install`), use `install.sh`. It copies the
modules to `/opt/pentest-agent`, builds an isolated venv **there**, installs
the dependencies into it, and writes a launcher to `/usr/local/bin/pentest-agent`
that runs the tool with that venv's interpreter — so it is immune to the
`ModuleNotFoundError` described above just like the Makefile install.

```bash
./install.sh                                   # -> /opt/pentest-agent, launcher in /usr/local/bin
LIBDIR=/opt/tools/pa BIN=~/.local/bin/pentest-agent ./install.sh   # override locations
```

It uses `sudo` for the `/opt` and `/usr/local/bin` writes, so it'll prompt for
your password. Unlike the `make` launcher (which runs the tool **in place** from
this checkout), `install.sh` runs the **copy** under `/opt`, so edits to the repo
don't take effect until you re-run it.

**Which one?** `make -f Makefile.pentest-agent install` for a live-editable,
per-user install from this checkout; `install.sh` for a frozen, system-wide
copy shared by all users.

---

## Usage (once installed)

```bash
pentest-agent https://site.tld            # full pipeline, learning mode on
pentest-agent 10.0.0.5 --quiet            # terse output
pentest-agent https://site.tld --deep     # RAGFlow-check plugins absent from the feed
pentest-agent https://site.tld --no-cleanup   # keep the planted shell
pentest-agent https://site.tld --mode safe    # confirm each action
```

> Only run this against WordPress sites you are **explicitly authorized** to test.
