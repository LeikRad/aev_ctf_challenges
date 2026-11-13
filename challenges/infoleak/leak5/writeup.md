# leak5 - Over-serialized field via verbose API mode (IDOR-ish)

| | |
|---|---|
| **Challenge** | leak5 |
| **Category** | INFOLEAK |
| **Points / Difficulty** | 250 / hard |
| **Target** | http://leak5.chal.deti:8014 ("API / Directory service") |
| **Leak class** | Excessive data exposure - API serializes a secret field in verbose mode |

## Hint
> A directory API with sequential ids. Read the client code; ask the API more than it shows.
> Profiles in a row - one keeps far more than it should. Count them, then ask more.

## Recon
`/api/users/<id>` returns `{email,id,username}` for sequential ids 1-7 (id=7 =
`admin`); 8+ = `{"error":"not found"}`. The default view hides the sensitive field.

The hint says "read the client code". `/static/app.js` (200) contains:
```js
// profile viewer
const ADMIN_PROFILE_ID = 7;
// loadProfile(ADMIN_PROFILE_ID);
```
So the client code's contribution is pointing at the **admin record (id 7)** - it does
*not* reveal the expand parameter. That part is server-side only.

## Approach
The expand parameter is `verbose=1`, found by **fuzzing** common "give me more fields"
params against id 7 (it is not referenced in `app.js`). Requesting the admin record
with it returns the full, over-serialized object.

## Exploitation - the exact request
```bash
curl -s 'http://leak5.chal.deti:8014/api/users/7?verbose=1'
```
(Of the sweep `fields/expand/include/full/verbose/all/format/details/show/admin`, only
`verbose=1` was honoured by the server.)

## Response fragment that carried the flag
```json
{"email":"admin@example.com","id":7,"username":"admin",
 "role":"admin","flag":"flag{8e23460cb92e293572152883f8a7c22f}"}
```
Default response omits `role` and `flag`; `verbose=1` serializes **the entire model**,
including fields never meant for the client.

## Flag
```
flag{8e23460cb92e293572152883f8a7c22f}
```

## Which field should never have been serialized? / Fix (task question)
- The **`flag`** field (a server-only secret) should never be serialized to any client
  under any mode. `role` is borderline but acceptable.
- **Fix without breaking the client:** serialize via an explicit **allow-list schema**
  (e.g. return only `id, username, email`, and `role` in verbose) instead of dumping
  the whole ORM object. `verbose` should add *more non-sensitive* fields, never expose
  model internals. Keep secrets off the user model entirely, or mark them
  non-serializable. The client keeps working because the fields it actually reads are
  unchanged.

## Root cause & remediation
- **Cause:** the verbose code path serializes the raw model (`return dict(user)`),
  leaking a secret attribute. Classic excessive-data-exposure / mass-assignment of
  output.
- **Fix:** response DTO/schema with field allow-list; never `jsonify` a raw DB row;
  review every "expand/verbose" mode for what it newly reveals.
