#!/usr/bin/env bash
H=10.110.3.72
PORTS="3000 8000 8010 8015 8018 8020 8081 8082 8083 8084"
for p in $PORTS; do
  echo "================ :$p ================"
  curl -s -D - -o /dev/null -m5 "http://$H:$p/" \
    | grep -iE '^(HTTP|Server|X-Powered-By|Set-Cookie|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options)'
  echo -n "  OPTIONS Allow: "
  curl -s -D - -o /dev/null -m5 -X OPTIONS "http://$H:$p/" | grep -i '^Allow:' || echo "(none)"
  tr=$(curl -s -o /dev/null -m5 -w '%{http_code}' -X TRACE "http://$H:$p/")
  echo "  TRACE -> HTTP $tr"
done
