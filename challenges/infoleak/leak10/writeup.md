# leak10 - Debug traceback leaks local variables

| | |
|---|---|
| **Challenge** | leak10 |
| **Category** | INFOLEAK |
| **Points / Difficulty** | 75 / introductory |
| **Target** | http://leak10.chal.deti:8019 ("Error lab") |
| **Leak class** | Debug mode / verbose error - stack trace exposing local variables |

## Hint
> Make it stumble - once it will spill its insides, look at what it bled.

## Recon
Port 8019 is a gunicorn Flask app with a single form that posts to
`/crash?msg=...`. During content discovery gobuster aborted here because **every**
path returns `500` with a ~1737-byte body - i.e. the app throws unhandled errors and
serves a full error page. Flask is running with `debug=True`, so that error page is
the interactive Werkzeug debugger, which dumps the traceback **and each frame's local
variables**.

## Approach
Trigger the error path and read the traceback. The `/crash` view deliberately raises
`RuntimeError(f"boom in {request.path}")`; because debug is on, the response includes
the source context of each frame plus its locals - and the `crash` frame holds a
`secret` local.

## Exploitation - the exact request
```bash
curl -s "http://leak10.chal.deti:8019/crash?msg=d"
```
(Equivalently: submit the form on the page, which navigates to `/crash?msg=...`.)

## Response fragment that carried the flag
```
  File "/app/app.py", line 43, in crash
    raise RuntimeError(f"boom in {request.path}")
    secret = 'flag{a955c19f4c2a3af15345f17c1933d166}'
RuntimeError: boom in /crash
```
The `secret = '...'` line is a **local variable** of the `crash` frame, exposed only
because the interactive debugger renders frame locals.

## Flag
```
flag{a955c19f4c2a3af15345f17c1933d166}
```

## Root cause & remediation
- **Cause:** `app.run(debug=True)` (Werkzeug debugger) left enabled in a reachable
  deployment. The debugger prints every frame's local variables on an unhandled
  exception, leaking any secret that happens to be in scope.
- **Fix:** never run with `debug=True` in production; set `FLASK_DEBUG=0`, register a
  generic 500 error handler that returns no stack trace, and keep secrets out of
  request-handling locals (load from env/secret store, don't bind to view locals).
  The PIN-protected debugger is still a risk - disable it entirely.
