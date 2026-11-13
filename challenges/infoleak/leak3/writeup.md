# leak3 - Directory listing exposes flag.txt

| | |
|---|---|
| **Challenge** | leak3 |
| **Category** | INFOLEAK |
| **Points / Difficulty** | 100 / easy |
| **Target** | http://leak3.chal.deti:8012 ("Media") |
| **Leak class** | Directory listing (autoindex) exposing a file |

## Hint
> Open shelving today, every drawer left ajar - come, take a long look.

## Recon
The landing page references a public directory (`/public/`). Content discovery hit it
as a 308 redirect to `/public/`, and the directory has **autoindex enabled**, so the
server renders a browsable list instead of a 403:
```bash
curl -s http://leak3.chal.deti:8012/public/
```
```html
<h2>Index of /public/</h2>
<ul>
  <li><a href="/public/readme.txt">readme.txt</a></li>
  <li><a href="/public/flag.txt">flag.txt</a></li>
</ul>
```

## Approach
With listing on, every file in the directory is enumerable - including ones not
linked from the UI. `readme.txt` is a decoy (`nothing to see here`); `flag.txt` is
the target.

## Exploitation - the exact request
```bash
curl -s http://leak3.chal.deti:8012/public/flag.txt
```

## Response fragment that carried the flag
```
flag{ecb15c4eafff3703a249c9058188bf92}
```

## Flag
```
flag{ecb15c4eafff3703a249c9058188bf92}
```

## Root cause & remediation
- **Cause:** directory autoindex/listing is enabled on `/public/`, so files that are
  not linked anywhere (like `flag.txt`) are still discoverable by browsing the index.
- **Fix:** disable directory listing (`Options -Indexes` on Apache, `autoindex off`
  on nginx, don't enable Flask static autoindex); do not store sensitive files under a
  web-served directory; serve only an explicit allow-list of public assets.

## Note
The wildcard DNS was visible here: a typo'd host (`leaeak3.chal.deti`) still resolved
to 10.110.3.72 and served the same app - any `*.chal.deti` label maps to the one host.
