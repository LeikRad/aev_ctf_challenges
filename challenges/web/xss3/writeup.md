# xss3 (Team card) - DOM-based XSS

| | |
|---|---|
| **Challenge** | xss3 (Team card) |
| **Category** | web (xss) |
| **Points / Difficulty** | 200 / medium |
| **Target** | http://xss3.chal.deti:8023 (tested locally on 127.0.0.1:8023) |
| **Bug** | CWE-79 - DOM-based cross-site scripting |

## Hint
> The card lives in the link; the server sends one page; your browser does the rest.

## Recon (black-box)
A "team card" builder: `/?card=<html>` renders a shareable card. The server sends
**one static page for every `card` value** - the page's own JavaScript reads the
`card` URL parameter and writes it into the card element with **`innerHTML`**,
client-side. So the payload **never appears in the server's response body**
(confirmed: `curl /?card=TEST` doesn't contain `TEST`) - the DOM-XSS tell.
Same flag mechanism: `grant()` + `/flag` gated on `xss_grant_xss3=1`.

## Approach
Because the sink is `innerHTML` executed after load:
- a `<script>` in `card` is **ignored** (browsers don't run `innerHTML`-inserted
  scripts);
- an `<img onerror>` event handler **does** fire.

So `<img onerror>` is mandatory here:
```
?card=<img src=x onerror=grant()>
```

## Exploitation
```
# browser only (payload executes client-side; curl won't trigger it):
http://xss3.chal.deti:8023/?card=<img src=x onerror=grant()>

# curl equivalent for the grant itself:
curl -s --cookie "xss_grant_xss3=1" http://xss3.chal.deti:8023/flag
```

## Flag
```
flag{xss3_local_verify}   # local placeholder; per-student on the real instance
```

## For the report
- **Class/confirm:** CWE-79 **DOM-based** XSS. Distinguished from reflected (xss1)
  by the test: the injected value is **absent from the HTTP response** and only
  the final rendered DOM contains it → the sink is client-side (`innerHTML`).
- **Why `<script>` fails but `<img onerror>` works:** HTML parsed into the DOM via
  `innerHTML` after load does not execute `<script>`; event-handler attributes do.
- **Impact:** same as reflected - arbitrary JS in the victim's session from a
  crafted link; no server round-trip makes it invisible to server-side WAFs/logs.
- **Fix:** don't assign untrusted input to `innerHTML`; use `textContent`, or
  sanitise (e.g. DOMPurify) before insertion; CSP as defense-in-depth. Server-side
  escaping can't help a purely client-side sink - the fix must be in the JS.

## Root cause & remediation
- **Cause:** `document.getElementById('card').innerHTML = params.get('card')` -   attacker-controlled URL param → `innerHTML` sink (CWE-79, DOM).
- **Fix:** `textContent` / sanitiser + CSP; the fix lives in the client code.

---

## XSS set - the three contexts (report summary)
| | sink | where it runs | `<script>`? | key tell |
|---|---|---|---|---|
| xss1 reflected | server reflects `q` into HTML | server response, on load | runs (if valid+ordered) | payload in HTTP response |
| xss2 stored | server stores note, renders to all | server response, every viewer | runs | persists across visitors |
| xss3 DOM | JS `innerHTML = ?card=` | client, after load | **ignored** | payload NOT in HTTP response |

`<img src=x onerror=...>` is the one payload that works in all three.
