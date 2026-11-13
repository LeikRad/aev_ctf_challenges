# True Names - SOLVED

| | |
|---|---|
| **Challenge** | True Names |
| **Category** | CRYPTO |
| **Points / Difficulty** | 100 |
| **Target** | `ctfd.chal.deti` (the CTFd node itself - *not* 10.110.3.72:9001) |
| **Lock class** | Vigenère cipher keyed by a name (known-plaintext recovery) |
| **Status** | **Solved.** Trace located in the CTFd landing-page HTML; key = `WINTERMUTE`. |

## Challenge text
> The construct says the Tessier-Ashpool AIs were never meant to know themselves.
> One of them has been leaving traces anyway: half-erased, locked, scattered where
> operators rarely look. One of those traces is on the node you came in through. It
> doesn't show on the map, and the lock on it isn't a number. It's a name.
> Find the trace. Learn the name. Bring back the flag. `jack-in://this-node/`

Hints (purchased):
- **The lock (10 pts):** "The lock is old: Nineteenth-century tradecraft, still in use in the Sprawl."
- **Secrets (20 pts):** "You know exactly how it begins. Line it up and the first secrets will fall out."

## Key insight - reading the riddle correctly
The earlier dead end came from misreading two phrases:
- **"the node you came in through" = the CTFd server (`ctfd.chal.deti`)**, not the lab
  target or the `:9001` service. This is why the professor said it's *"the only one
  solvable without the remote session"* - CTFd is reached directly, no VPN. The `:9001`
  echo service is a red herring belonging to another task (pure `Hello, <x>` / `Goodbye.`,
  no name branch).
- **"doesn't show on the map" + "where operators rarely look" = page source**, not a
  route on the sitemap. The trace is an HTML attribute that never renders.

## Recon - finding the trace
The CTFd front page is a custom "NEUROMANCER" theme (Admin > Pages, route `/`). Dumping
the raw HTML of the landing page and reading the markup (not the rendered page) reveals a
planted attribute on a `<div>`:

```bash
curl -s http://ctfd.chal.deti/ | grep -oE 'data-trace="[^"]*"'
# data-trace="WMI{ml3_jws_4u0z3_pp3_c0kx}"
```

That `WMI{...}` blob is the "trace" - a flag-shaped ciphertext.

## Approach - the lock is a named Vigenère
- **Hint 1 ("19th-century tradecraft, a name not a number") = Vigenère**, keyed by a word
  rather than a numeric shift.
- **Hint 2 ("you know exactly how it begins, line it up") = known-plaintext / crib-drag.**
- The brief says the Tessier-Ashpool AIs are *learning their name* → in *Neuromancer*
  those AIs are **Wintermute** and **Neuromancer**. So the key is one of those names.

The cipher touches **letters only**; digits (leetspeak), `_`, `{`, `}` pass through
unchanged. Trying each candidate name as the key, the readable decryption picks the winner.

## Exploitation - recover the name, decrypt the trace
```python
#!/usr/bin/env python3
CIPHER = "WMI{ml3_jws_4u0z3_pp3_c0kx}"

def vigenere_decrypt(ct, key):
    out, j = [], 0
    for ch in ct:
        if ch.isalpha():
            k = ord(key[j % len(key)].lower()) - 97
            base = 65 if ch.isupper() else 97
            out.append(chr((ord(ch) - base - k) % 26 + base)); j += 1
        else:
            out.append(ch)          # digits, _, { } untouched
    return "".join(out)

for name in ["WINTERMUTE", "NEUROMANCER"]:   # the two Tessier-Ashpool AIs
    print(f"{name:12} -> {vigenere_decrypt(CIPHER, name)}")
```

Output - one key is clean, the other is noise:
```
WINTERMUTE   -> aev{th3_sky_4b0v3_th3_p0rt}
NEUROMANCER  -> <garbage>
```

Cross-check (crib-drag proves it non-circularly): assuming the 3-char tag, a *wrong*
prefix gives garbage key letters, the *right* one gives a name-start:
```
crib 'fla' -> key 'rbi'   (noise)
crib 'aev' -> key 'win'   -> the only Neuromancer AI starting 'win' = WINTERMUTE
```

## The name (the lock)
```
WINTERMUTE
```

## Flag
```
AEV{th3_sky_4b0v3_th3_p0rt}
```
Note: the Vigenère plaintext decrypts with a lowercase tag (`aev{...}`), but the CTFd
submission is case-sensitive and expects the tag uppercased: **`AEV{th3_sky_4b0v3_th3_p0rt}`**.

The plaintext `th3_sky_4b0v3_th3_p0rt` is leetspeak for *"the sky above the port"* - the
opening line of William Gibson's *Neuromancer*. That is what "you know exactly how it
begins" pointed at.

## Root cause & remediation
- **Cause:** a secret (the Vigenère-locked flag) was embedded client-side in a
  `data-trace` attribute of the CTFd theme's landing page - recoverable by anyone who
  reads page source. A name-keyed classical cipher adds no real confidentiality; the key
  is guessable straight from the challenge's own theming.
- **Fix:** never ship secrets in client-delivered HTML/attributes; if a puzzle *must*
  embed ciphertext, don't let the surrounding theme telegraph the key.
