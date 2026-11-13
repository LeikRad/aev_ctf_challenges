#!/usr/bin/env python3
"""Prefix-aware route fuzzer for leak2 (:8011). Uses a LOCAL wordlist only
(the lab firewall blocks external downloads). Flat /word brute already failed,
so we also try words under common API/status prefixes."""
import requests, sys
from concurrent.futures import ThreadPoolExecutor

BASE = "http://leak2.chal.deti:8011"
WORDLIST = "/usr/share/dirb/wordlists/common.txt"
PREFIXES = ["", "status/", "api/", "api/status/", "internal/", "debug/", "v1/", "admin/"]

words = [w.strip() for w in open(WORDLIST, errors="ignore") if w.strip() and not w.startswith("#")]
paths = [p + w for p in PREFIXES for w in words]
print(f"[*] {len(words)} words x {len(PREFIXES)} prefixes = {len(paths)} requests", file=sys.stderr)

s = requests.Session()
def probe(path):
    try:
        r = s.get(f"{BASE}/{path}", timeout=5, allow_redirects=False)
        if r.status_code != 404:
            return (r.status_code, len(r.content), path)
    except Exception:
        return None

with ThreadPoolExecutor(max_workers=10) as ex:
    for hit in ex.map(probe, paths):
        if hit:
            print(f"{hit[0]}  len={hit[1]:<6} /{hit[2]}")
