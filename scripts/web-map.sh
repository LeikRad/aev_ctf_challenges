#!/usr/bin/env bash
HOST=10.110.3.72
PORTS="3000 8000 8010 8011 8012 8013 8014 8015 8016 8017 8018 8019 8020 8021 8022 8023 8081 8082 8083 8084"
printf "%-6s %-6s %-28s %-30s %s\n" PORT CODE SERVER REDIRECT TITLE
for p in $PORTS; do
  hdr=$(curl -s -m 5 -D - -o /dev/null "http://$HOST:$p/")
  code=$(printf '%s' "$hdr" | awk 'NR==1{print $2}')
  srv=$(printf '%s' "$hdr" | grep -i '^server:' | cut -d' ' -f2- | tr -d '\r')
  loc=$(printf '%s' "$hdr" | grep -i '^location:' | cut -d' ' -f2- | tr -d '\r')
  title=$(curl -s -m 5 "http://$HOST:$p/" | grep -ioE '<title>[^<]*</title>' | head -1 | sed -E 's/<\/?title>//g')
  printf "%-6s %-6s %-28s %-30s %s\n" "$p" "${code:-?}" "${srv:-"-"}" "${loc:-"-"}" "${title:-"-"}"
done
