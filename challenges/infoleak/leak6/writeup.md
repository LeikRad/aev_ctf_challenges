# leak6 - Secret carried in a JWT payload

| | |
|---|---|
| **Challenge** | leak6 |
| **Category** | INFOLEAK |
| **Points / Difficulty** | 200 / medium |
| **Target** | http://leak6.chal.deti:8015 ("Auth service") |
| **Leak class** | Sensitive data in a (readable) JWT claim |

## Hint
> The badge you carry - peel back the layers and read, see what it carries.
> Log in. Inspect the token you were given. Tokens are documents.

## Recon
The landing page is a login form defaulting to `user=guest`. Logging in returns a
JSON body with a `token` - a JWT (three base64url segments `header.payload.signature`).

## Approach
A JWT is **signed, not encrypted**. The payload is plain base64url that anyone holding
the token can read - no key needed. So just decode the middle segment. The three
segments are split on `.`:  `header.payload.signature`.

## Exploitation - the exact request
```bash
# 1. get the token
curl -s -X POST http://leak6.chal.deti:8015/login -d 'user=guest'
```

## Decoding by hand (base64url, no JWT library)
base64url = standard base64 with `+`->`-`, `/`->`_`, and `=` padding stripped. To
decode manually: (a) swap `-_` back to `+/`, (b) re-pad to a multiple of 4 with `=`,
(c) map each char to its 6-bit value and regroup into 8-bit bytes.

Worked example on the first 4 chars of the header `eyJh`:
```
char  base64 index   6 bits
 e        30         011110
 y        50         110010
 J         9         001001
 h        33         100001
regroup 24 bits -> 3 bytes: 01111011 00100010 01100001
                            = 0x7B     0x22     0x61
                            =  {        "        a      -> '{"a'  (start of {"alg")
```
Every following group of 4 chars yields 3 more bytes the same way, giving:
```
header : {"alg": "HS256", "typ": "JWT"}
payload: {"sub":"guest","role":"user","feature_flags":{"show_admin":true},
          "flag":"flag{e13f117666b483b7dd760898e50756d9}"}
```
(As a one-liner cross-check - not the manual method - `echo '<seg>==' | tr '_-' '/+' |
base64 -d` produces the same bytes.)

## Response fragment that carried the flag
```json
// header:  {"alg": "HS256", "typ": "JWT"}
// payload:
{"sub": "guest", "role": "user",
 "feature_flags": {"show_admin": true},
 "flag": "flag{e13f117666b483b7dd760898e50756d9}"}
```

## Flag (dynamic - a fresh flag per token)
The server mints a **new flag in every issued token**; the checker accepts whatever
flag rides in a validly-signed token. Two observed samples, both accepted by CTFd:
```
flag{e13f117666b483b7dd760898e50756d9}
flag{b42694d7c0bf84ac1887be4ff66fddf8}
```
Each was independently base64url-decoded from its own token's payload (verified, not
guessed). So the "solve" is: log in → decode your token's payload → submit that flag.

## Decoder scripts
- `decode_jwt.py` - splits on `.`, base64url-decodes each segment
  (`base64` only, no JWT library).
- A zero-import variant (implements the base64 alphabet by hand) is in the writeup
  method above - char -> 6 bits -> regroup into bytes.

## Signed vs. readable (the task's question)
- **Header + payload** are just base64url text - **readable by anyone**, not secret.
- **Signature** = `HMAC-SHA256(base64url(header) + "." + base64url(payload), key)`.
- The signature only proves the token **wasn't tampered with**; it provides
  **no confidentiality**. That is the whole problem: putting `flag`/secrets in a JWT
  claim exposes them to every client, even though they can't *forge* a new token
  without the HMAC key. Integrity != confidentiality.

## Root cause & remediation
- **Cause:** a secret was placed in a JWT claim, treating "signed" as if it meant
  "hidden". JWT payloads are world-readable.
- **Fix:** never store secrets/PII in a JWT payload; keep claims to non-sensitive
  identifiers; if data must be confidential, use an encrypted token (JWE) or an opaque
  server-side session id. Also drop the `feature_flags.show_admin` leak - it advertises
  privileged functionality to a guest.
