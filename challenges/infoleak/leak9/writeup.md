# leak9 - Comments left in the source

| | |
|---|---|
| **Challenge** | leak9 |
| **Category** | INFOLEAK |
| **Points / Difficulty** | 50 / introductory |
| **Target** | http://leak9.chal.deti:8018 (="Acme Corp") |
| **Leak class** | Sensitive data in HTML comment (source disclosure) |

## Hint
> What you see is less - the page keeps its private thoughts, read between the lines.

## Recon
Port 8018 is one of the gunicorn Flask apps; its landing page titles itself
"Acme Corp" and renders only `Welcome to Acme Corp` / `Nothing to see here. Please
move along.` Nothing on the *rendered* page is useful - the hint ("read between the
lines", "what you see is less") points at the raw HTML the server sent, not the
visual page.

## Approach
The rendered DOM hides HTML comments; the server still ships them. View source
(or Inspect Element / `curl`) to read everything between the tags.

## Exploitation - the exact request
```bash
curl -s http://leak9.chal.deti:8018/ | grep -i flag
```
Or in the browser: right-click → Inspect Element / View Source.

## Response fragment that carried the flag
```html
<body>
  <!--TODO: remove this debug marker before shipping-->
  <!--FLAG: flag{7ae72615cddc55bf5389b2164bcacf1f}-->
  <h1>Welcome to Acme Corp</h1>
  <p>Nothing to see here. Please move along.</p>
  <button>edit</button>
</body>
```

## Flag
```
flag{7ae72615cddc55bf5389b2164bcacf1f}
```

## Root cause & remediation
- **Cause:** a debug/developer comment containing the secret was left in the template
  and shipped to production. Comments are invisible in the rendered page but fully
  present in the response body.
- **Fix:** strip comments from templates in the production build; never place secrets
  in client-deliverable markup; add a CI check that greps built HTML for `FLAG`/
  `TODO`/`DEBUG` markers before deploy.
