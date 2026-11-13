# Guestbook - blind SQLi on an INSERT (MariaDB), error-flash oracle

| | |
|---|---|
| **Challenge** | Guestbook |
| **Category** | SQLI |
| **Points / Difficulty** | 400 / expert |
| **Target** | http://sqli6.chal.deti:8035 |
| **DB** | **MariaDB** (not SQLite like the earlier sqli challenges) |
| **Bug** | CWE-89 - blind SQL injection on a write (INSERT) statement |

## Hint
> Every note gets the same thanks. Sometimes it takes longer. Measure the silence.

## Recon
- `POST /` with `name` + `message` → `INSERT INTO notes(name,message)
  VALUES('<name>','<message>')`, **`name` concatenated raw**.
- Response is always the same "thanks"; "Recent notes" just reflects your input
  (not a data channel).
- **Structure found by probing** (comment-terminated breakouts, judged by whether
  the row stored): a single quote errors the insert; 2-column `VALUES`; working
  breakout = `name=X','m')-- `.
- **Error tell:** an invalid query shows a distinct flash -   `"The book was a bit ruffled - your note was not saved."`

## Approach
The intended channel is **time-based** (`SLEEP(3)` inside the INSERT). But the
error flash is a cleaner/faster **boolean oracle**: break out of `name`, comment
the rest, and put a `CASE` in the message slot that raises a **runtime error only
when the predicate is true**:

```
name = x', (CASE WHEN (<cond>) THEN (9223372036854775807*9223372036854775807) ELSE 0 END))--
```
cond TRUE → BIGINT overflow → INSERT errors → **"ruffled"**; FALSE → `0` → saved.

Extract `vault.secret` by binary-searching each byte:
```
(SELECT ascii(substring(secret,i,1)) FROM vault LIMIT 1) > mid
```

### Gotchas that cost time (all from assuming SQLite)
1. **DB is MariaDB** → `unicode()`/SQLite idioms are wrong; use `ascii()`,
   `substring()`.
2. **Case-insensitive collation** → a string `substr > char(mid)` comparison
   garbled output (`{`→`` ` ``, digits→letters). Fix: compare **`ascii()` numerically**.
3. **Flask flash in the session cookie** → reusing a `requests.Session` desynced
   which response carried "ruffled" (symptom: every char read as 0). Fix: one
   fresh request per oracle call.

## Flag
```
flag{7fd7626b19a305280dcf76829557ed88}
```

## For the report
- **Oracle:** error-flash boolean (`"ruffled"` present ⇔ predicate true), via an
  overflow raised inside the INSERT's `CASE`. (Time-based `SLEEP(3)` is the
  intended equivalent.)
- **Timing threshold / noise (intended channel):** baseline POST ≈ 0.06 s with
  jitter; a `SLEEP(3)` payload lands ~3 s, so a threshold of ~1.5 s cleanly
  separates true/false even with the lab's noisiest channel - repeat on
  borderline reads.
- **Requests per character:** binary search over `[0,127]` = **7 requests/char**
  (+ ~8 for the length) → **~274 total** for the 38-byte secret - the *same
  request count as The Daily Byte*. The difference is **cost per request**: the
  error/boolean channel is instant, whereas the intended time channel pays ~3 s
  on every *true* comparison (~minutes end-to-end).

## Root cause & remediation
- **Cause:** "it's only a guestbook" is no defence - the `name` value is
  concatenated into a write statement (CWE-89), so an attacker runs arbitrary
  sub-SELECTs (here reading `vault.secret`) even with no data echoed.
- **Fix:** parameterise the INSERT (`VALUES(?, ?)`); never build SQL by string
  concatenation; keep secrets out of a DB reachable by the public app; rate-limit
  to blunt the hundreds of inferential requests.
