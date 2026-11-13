# leak8 - Hidden path disclosed by robots.txt

| | |
|---|---|
| **Challenge** | leak8 |
| **Category** | INFOLEAK |
| **Points / Difficulty** | easy |
| **Target** | http://leak8.chal.deti:8017 ("Public site") |
| **Leak class** | Robots directive - `Disallow` reveals a "hidden" path |
| **Note** | Scoreboard had no submit field for this one; solved + documented anyway |

## Hint
> Crawler etiquette is documented somewhere. Read the document.

## Recon
The landing page says *"Public site - Nothing interesting. crawlers: see our rules."*
`robots.txt` is the "document" referenced. Content discovery (gobuster) also flagged
`/robots.txt` (200, 39 bytes):
```bash
curl -s http://leak8.chal.deti:8017/robots.txt
```
```
User-agent: *
Disallow: /admin-secret/
```
`Disallow` does not hide anything - it only asks crawlers not to index it. It is, in
effect, a signpost to the sensitive path.

## Approach
Request the disallowed path directly.

## Exploitation - the exact request
```bash
curl -s http://leak8.chal.deti:8017/admin-secret/
```

## Response fragment that carried the flag
```html
<pre>flag{70d7874ef9f8714a4e0745cb84f9d0d5}</pre>
```

## Flag
```
flag{70d7874ef9f8714a4e0745cb84f9d0d5}
```

## Root cause & remediation
- **Cause:** security-by-obscurity - a sensitive route protected only by a
  `robots.txt` `Disallow`. `robots.txt` is world-readable and advertises the path to
  anyone who looks; it is an enumeration aid, not an access control.
- **Fix:** put real authentication/authorization on `/admin-secret/`; never rely on
  `robots.txt` to conceal anything; if a path must stay private, it should return
  401/403 without credentials and must not be listed in `robots.txt`.
