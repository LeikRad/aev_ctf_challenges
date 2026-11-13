# QuickShip_Tracker - sensitive id leaked in a GET query string

| | |
|---|---|
| **Challenge** | QuickShip_Tracker |
| **Category** | AUTH |
| **Points / Difficulty** | 100 / easy |
| **Target** | http://auth3.chal.deti:8062 |
| **Auth weakness** | CWE-598 - sensitive info in a GET request query string |

## Hint
> A story well told carries one line too many: a link, meant for one.

## Recon
The site publishes customer reviews ("a story well told"). One VIP review pastes
the *direct tracking link* the support agent sent them - including the private
shipment id in the URL:

> "…The support agent even sent me a direct link so I could keep an eye on it:
> `/track?sid=1fd5a60978436d3e`. Five stars." - R. Okafor (verified VIP customer)

## Approach
CWE-598: the shipment id is a sensitive, access-granting value carried in a GET
query string, so it leaks anywhere the URL goes - here, straight into
user-visible review text. The tracking id was "meant for one" recipient but is
now public. Just request the leaked link.

## Exploitation - the exact request
```bash
curl -s "http://auth3.chal.deti:8062/track?sid=1fd5a60978436d3e" | grep -o 'flag{[^}]*}'
```

## Flag
```
flag{df1504fca91dbdb348f47692d725bcf3}
```

## Root cause & remediation
- **Cause:** an access-granting identifier is passed in the URL query string
  (CWE-598), so it ends up in browser history, server/proxy logs, `Referer`
  headers, and - as here - in content users can paste publicly. No
  authentication binds the tracking view to the real customer.
- **Fix:** don't put secrets/access tokens in GET URLs; require an
  authenticated session tied to the order, use unguessable *and* short-lived
  tokens delivered out-of-band, and scrub user-submitted content for leaked
  internal links.
