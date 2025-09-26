#!/usr/bin/env bash
FILE="$1"
if [ -z "$FILE" ]; then
  echo "Usage: ./scripts/pushnote.sh notes/daily/YYYY-MM-DD-soc.md"
  exit 1
fi
git add "$FILE"
git commit -m "docs(daily): $(date +%F) — SOC — $(head -n1 "$FILE" | sed 's/^#\s*//')"
git push origin main
echo "Pushed $FILE"
