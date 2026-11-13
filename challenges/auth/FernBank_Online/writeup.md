# FernBank_Online - session not invalidated on logout (replay a leaked sid)

| | |
|---|---|
| **Challenge** | FernBank_Online |
| **Category** | AUTH |
| **Points / Difficulty** | 100 / easy |
| **Target** | http://auth14.chal.deti:8073 |
| **Auth weakness** | CWE-613 - insufficient session expiration |

## Hint
> Goodbye at the door, yet the key still turns inside - no one told the lock.

## Recon
- Session cookie is **`sid`** - a raw 32-hex id (not signed), `HttpOnly`,
  `Secure=false`, `SameSite=Lax`.
- `/diagnostics` is an **Ops session trace** that logs manager session ids
  "for troubleshooting," each annotated *"manager shift-report probe, session
  closed by client"* - i.e. the manager **logged out**.
- `/dashboard` is the gated manager console.

## Approach
CWE-613: logout is only client-side ("closed by client") - the server never
expires or revokes the `sid`, so a logged-out manager session "still turns the
lock." The diagnostics page leaks those manager session ids, so we just set our
`sid` cookie to a leaked one and load `/dashboard`. (The newest trace entry is
your own probe; use the pre-existing manager ids.)

## Exploitation - the exact request
```bash
# replay a leaked, still-valid manager session id
curl -s -b 'sid=1cb5c0fd1e6e1277766bc82346b9124d' \
     http://auth14.chal.deti:8073/dashboard | grep -o 'flag{[^}]*}'
```

## Flag
```
flag{c9a36182b063c7dc7a7b1b9c1318a6b8}
```

## Root cause & remediation
- **Cause:** sessions are never invalidated server-side on logout or after
  inactivity (CWE-613), and manager session ids are additionally exposed in a
  diagnostics log - so a stolen/old id authenticates indefinitely.
- **Fix:** on logout, destroy the session server-side (delete the record /
  rotate the id); enforce idle + absolute session timeouts; never log session
  ids; bind sessions to additional context and regenerate the id on privilege
  change.
