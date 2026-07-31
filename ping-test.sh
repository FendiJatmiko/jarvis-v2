#!/usr/bin/env bash

INPUT="$1"
OUTPUT="reachable.txt"

>"$OUTPUT"

while IFS= read -r host; do
  [[ -z "$host" || "$host" =~ ^# ]] && continue

  if ping -c1 -W2 "$host" >/dev/null 2>&1; then
    echo "[OK] $host"
    echo "$host" >>"$OUTPUT"
  else
    echo "[FAIL] $host"
  fi
done <"$INPUT"

echo
echo "Reachable hosts saved to $OUTPUT"
