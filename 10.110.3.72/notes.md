# 10.110.3.72 — working notes

Target: `10.110.3.72` (aka `chal.deti` and every `*.chal.deti`). Single challenge
host; all challenges are name+port virtual hosts on this one box.

## Raw outputs in this folder
| File | Command | Purpose |
|------|---------|---------|
| `scan-discovery.txt` | `nmap -sn 10.110.3.0/24` | host discovery (subnet) |
| `scan-infra.txt` | `nmap -sV -T3 --top-ports 1000 10.110.3.1 .2 .4` | infra fingerprint |
| `scan-versions.txt` | `nmap -sV -T3 -p- --max-retries 2 10.110.3.72` | full TCP + versions |
| `scan-udp.txt` | `nmap -sU -T3 --top-ports 50 10.110.3.72` | UDP top-50 (nothing useful) |
| `scan-udp-2.txt` | `nmap -sUV -T3 -p 8024 10.110.3.72` | confirmed 8024/udp = SNMP |
| `snmp-walk.txt` | `scapy` walker (`challenges/network/snmp1/`) | full SNMP walk → flag |
| `web/port-titles.txt` | `nmap --script http-title` | titles (only 8000 fired) |
| `web/web-map.txt` | `scripts/web-map.sh` | port · code · Server · redirect · title |
| `web/body-peek.txt` | `scripts/body-peek.sh` | landing-page body of blank ports |

## Host roles (subnet)
- `10.110.3.1` — gateway + DNS (dnsmasq 2.91 on :53) + Proxmox node (:3128)
- `10.110.3.2` — Proxmox node (infra only)
- `10.110.3.4` — Proxmox node (infra only)
- `10.110.3.72` — **challenge host** (our target)

All three infra nodes share: OpenSSH 10.0p2 (Debian), rpcbind :111, Proxmox VE
REST API :3128. Do NOT touch :3128 — management plane, out of scope per RoE.

## DNS
- Nameserver seen in container `/etc/resolv.conf`: `10.139.0.1` (podman internal
  resolver, forwards upstream to dnsmasq on `.1`).
- **Wildcard confirmed:** `*.chal.deti` → `10.110.3.72` for ANY label
  (`test`, `6525-27930`, etc. all resolve). Consequence: a name resolving proves
  nothing about whether that service is up — only a port probe does.
- Every challenge has its own vhost name, all pointing at .72, differentiated by
  port (`leak1.chal.deti:8010`, `wordpress.chal.deti:8084`, `snmp1.chal.deti:8024/udp`).

## TCP services on .72 (from scan-versions.txt)
- 22   OpenSSH 10.0p2 (infra)
- 3000 Node — OWASP Juice Shop (stock app, Task 2 CVE target)
- 8000 gunicorn — CTFd scoreboard ("AEV")
- 8010-8023 gunicorn ×14 — Flask info-leak apps
- 8081-8084 Apache (mixed 2.4.7 Ubuntu / 2.4.25 / 2.4.67 Debian) — PHP apps
- 9001 custom TCP socket — prompts "What's your name?" (= CRYPTO "True Names")
- 5355 filtered (LLMNR, ignore)

## UDP service on .72 — snmp1 (SOLVED)
- 8024/udp = SNMP (non-standard port), community `public`, v1/v2c.
- **Abnormal:** server replies with a SET-PDU (tag 0xa3) instead of GET-RESPONSE
  (0xa2) → net-snmp's `snmpwalk`/`snmpget` abort ("Expected RESPONSE-PDU but got
  SET-PDU"). Worked around by reading replies off the wire (tcpdump) and by a
  scapy walker that ignores the bad PDU tag.
- Flag lives in private enterprise OID `1.3.6.1.4.1.99999.1.1.0`, outside the
  standard system group — so you must WALK, not just read sysDescr/contact/location.
- **FLAG: `flag{3cad557d9709a6a658ae582ce33ab216}`**

## Port -> CTFd challenge map (cross-checked against challenge descriptions)
| Port | Stack | Challenge | Clue / leak type |
|------|-------|-----------|------------------|
| 8010 | gunicorn | leak1 (150) | editor backup "dusty twin" (`config.py~`/`.swp`) |
| 8011 | gunicorn | leak2 (150) | `/status` "confesses the door has no key" |
| 8012 | gunicorn | leak3 (100) | directory listing "every drawer left ajar" |
| 8013 | gunicorn | leak4 (200) | git history "changes thrown away / old pages" |
| 8014 | gunicorn | leak5 (250) | IDOR / user enumeration |
| 8015 | gunicorn | leak6 (200) | JWT "badge, peel back the layers" |
| 8016 | gunicorn | leak7 (300) | boolean oracle "says yes one letter" |
| 8017 | gunicorn | leak8 (easy) | robots.txt "crawler etiquette" |
| 8018 | gunicorn | leak9 (50) SOLVED | HTML comments "read between the lines" |
| 8019 | gunicorn | leak10 (75) SOLVED | error/stack trace "make it stumble, it bleeds" |
| 8020 | gunicorn | notes1 (web) | access-model leak; guest account |
| 8024/udp | SNMP | snmp1 (100) SOLVED | this box — flag above |
| 8084 | Apache 2.4.67 | wordpress (100) | outdated WP core, flag outside web root |
| 9001 | custom | True Names (100) SOLVED | DECOY prompt — real trace was in CTFd landing-page HTML; see note below |

> **True Names note:** 9001 is a red herring (plain `Hello, <x>` / `Goodbye.` echo, no
> name branch). "The node you came in through" = the CTFd server (`ctfd.chal.deti`). A
> Vigenère ciphertext `WMI{ml3_jws_4u0z3_pp3_c0kx}` was hidden in a `data-trace` HTML
> attribute of the landing page. Key = **WINTERMUTE** (Tessier-Ashpool AI). Flag =
> **`AEV{th3_sky_4b0v3_th3_p0rt}`** (leetspeak for Neuromancer's opening line). Solvable
> fully offline. Full writeup: `challenges/crypto/true-names/writeup.md`.

## Stock vulnerable apps (Task 2 CVE targets — confirmed)
- 3000  OWASP Juice Shop (Node)
- 8081  bWAPP            (Apache 2.4.7 Ubuntu)    — title "bWAPP - Login"
- 8082  DVWA v1.10       (Apache 2.4.25 Debian)   — version leaked in <title>
- 8083  Mutillidae       (Apache 2.4.7 Ubuntu)
- 8084  WordPress        (Apache 2.4.67 Debian)   — also the `wordpress` challenge
Evidence: `web/stock-apps.txt`.

## 8021-8023 — the XSS challenges (xss1/xss2/xss3)
8021 (Lab recipes), 8022 (Bench log), 8023 (Team card) are the **web XSS challenges
xss1/xss2/xss3** — NOT filler. The app titles are textbook reflected/stored-XSS surfaces.
Exact xssN↔port mapping and release status TBD (may not be live on the scoreboard yet).
The four stock apps (juiceshop/bWAPP/DVWA/Mutillidae) are likewise named CTFd challenges
used in LATER exercises, beyond this info-gathering task.
=> A port scan over-reports AND under-maps: cross-check against the full CTFd challenge
list (incl. unreleased/future), not just the scoreboard grid.

## Anomalies to report (RoE)
1. **8084 (wordpress)** returned `WARNING: Failed to daemonise ... No route to
   host (113)` instead of a page during `body-peek` — broken/flapping backend.
2. **leak8** not shown on the scoreboard grid at first view, but live on :8017 — re-confirm.
3. **SNMP SET-PDU** mislabeling on 8024 (documented above) — breaks standard tooling.

## Still TODO (out of this info-gathering scope — later, within RoE)
- Solve wordpress (:8084) — vector identified, blocked by backend outage.
  (leak1-10, snmp1, notes1, True Names all SOLVED; wpscan done.)
- `scan-udp.txt` note: top-50 UDP found nothing; 8024 only found because the brief
  pointed at it. A wider `-sU` sweep would be needed to be exhaustive.

---

# Task 2 — Version & CVE enumeration

Sources: `scan-versions.txt` (`-sV`), `vulners.txt` (`--script vulners`),
`web/app-versions.txt` (app-layer fingerprinting), `web/stock-apps.txt`.

## Service/software inventory with versions
| Port | Software | Version | Notes |
|------|----------|---------|-------|
| 22 | OpenSSH | 10.0p2 (Debian 7+deb13u4) | infra, out of scope |
| 3000 | OWASP Juice Shop (Node) | 20.2.0 | intentionally vulnerable by design |
| 8000/8010-8023 | gunicorn (Flask) | not disclosed | hardened; CTFd + leak apps |
| 8081 | bWAPP + Apache httpd | 2.4.7 (Ubuntu 14.04) | PHP app; version hidden pre-auth (~2.2) |
| 8082 | DVWA + Apache httpd | app v1.10 / 2.4.25 (Debian) | version leaked in <title> |
| 8083 | Mutillidae II + Apache | app 2.6.62 / PHP 5.5.9 / 2.4.7 (Ubuntu) | PHP 5.5.9 EOL since 2016 |
| 8084 | WordPress + Apache | core TBD (wpscan) / 2.4.67 (Debian) | challenge: core unpatched |
| 9001 | custom socket | n/a | "True Names" crypto |

## vulners triage — real vs noise
- The vulners output (1346 lines) is a **version-banner match only**. It lists the
  entire CVE history of each Apache branch; it cannot distinguish a backported-but-
  patched Debian/Ubuntu build from a genuinely vulnerable one => mostly **noise** as
  presented.
- The feed is **lab-seeded / forward-dated** (SSH block shows `CVE-2026-xxxx`), so
  treat the scores as indicative only, not authoritative.
- **Signal = relative exposure**, which tracks Apache age:
  - 2.4.7 (Ubuntu 14.04, EOL) on 8081 & 8083 — largest surface (~169 CVE refs, 61 exploits)
  - 2.4.25 (Debian) on 8082 — ~166 refs, 69 exploits
  - 2.4.67 (Debian, ~2023) on 8084 — smallest (~67 refs, 12 exploits)
- Config-dependent Apache bugs (e.g. Optionsbleed CVE-2017-9798 on 2.4.25, mod_cgi
  issues on 2.4.7) only matter if the module/config is enabled — verify with the
  OPTIONS/TRACE checks in Task 5 before claiming them.

## Realistic CVE / exploitability assessment
| Component | Headline issue | Real-world refs | Exploitability in this lab |
|-----------|----------------|-----------------|----------------------------|
| PHP 5.5.9 (Mutillidae host) | **EOL since 2016, unsupported** | httpoxy CVE-2016-5385, many | High — no vendor patches at all |
| Apache 2.4.7 (Ubuntu 14.04) | EOL distro, old branch | CVE-2014-0226, CVE-2019-0211 (local) | Medium — mostly local/DoS/config-gated |
| Apache 2.4.25 | Optionsbleed, mod_mime | CVE-2017-9798, CVE-2017-7679 | Medium — only if config enables it |
| Apache 2.4.67 | recent, minor | few | Low |
| WordPress core | **outdated core** (per challenge) | depends on exact ver → wpscan | High — primary target, enumerate with wpscan |
| Juice Shop 20.2.0 | intentionally vulnerable | n/a (by design) | app-layer, not CVE-driven |
| DVWA v1.10 / bWAPP / Mutillidae | intentionally vulnerable | n/a (by design) | app-layer, not CVE-driven |

## Conclusions (Task 2)
1. The CVE-scan's value here is **triage, not a finding list**: banner matching over-
   reports and the feed is lab-seeded. The genuinely actionable items are the two
   **EOL components** — PHP 5.5.9 and the Ubuntu-14.04-era Apache 2.4.7 — which get
   no upstream security fixes regardless of CVSS.
2. The four training apps are **deliberately vulnerable at the app layer**; their
   stock-app nature matters more than their web-server CVEs. Treat Apache/PHP CVEs as
   context, not the objective.
3. **WordPress is the one real CVE target** — the challenge states the core is
   unpatched; the exact core version + plugin CVEs come from `wpscan` (Task 3).
4. Recommendations (realistic): suppress version banners (`ServerTokens Prod`,
   remove `readme.html`, strip feed/OPML generator, drop `X-Powered-By`); retire the
   EOL PHP/Apache or isolate these apps to a lab-only network; patch WordPress core
   and move secrets out of the web root. No such thing as perfect security — do the
   banner suppression + WordPress update first (highest impact / lowest effort).

---

# Task 3 — Web content discovery

Tools: gobuster (dirb `common.txt` + `big.txt`), wpscan. Outputs under `web/`:
`404-baseline.txt`, `scan-80XX-gobuster.txt`, `scan-80XX-big.txt`, `wordpress-wpscan.txt`.

## 404 baseline (do this first)
All gunicorn hosts return a clean `404 NOT FOUND`, `Server: gunicorn`, body 207 bytes
for nonexistent paths (`web/404-baseline.txt`). => gobuster's default 404 filtering
works; no length/status exclusion needed. Exception: 8019 returns **500 + 1737 bytes
for every path** (debug error page) — gobuster aborts ("everything matches"); that
behaviour IS the leak (leak10).

## Content-scan hits (common.txt + -x bak,py,md,txt) and classification
| Port | Chall | Hit | Leak class | URL |
|------|-------|-----|------------|-----|
| 8012 | leak3 | `/public` 308 -> `/public/` | directory listing | http://10.110.3.72:8012/public/ |
| 8013 | leak4 | `/.git/HEAD` 200, `/app.py` 200 | VCS metadata + source exposure | http://10.110.3.72:8013/.git/ |
| 8017 | leak8 | `/robots.txt` 200 | robots directive -> `Disallow: /admin-secret/` | http://10.110.3.72:8017/robots.txt |
| 8016 | leak7 | `/oracle` 200 (3 bytes) | boolean oracle endpoint | http://10.110.3.72:8016/oracle |
| 8015 | leak6 | `/login` 405 | auth endpoint (leak = issued token) | http://10.110.3.72:8015/login |
| 8020 | notes1| `/login` 405 | auth endpoint (leak = access model) | http://10.110.3.72:8020/login |

**Exposing something they should not:** 8012 (dir listing), **8013 (.git + app.py —
worst)**, 8017 (robots reveals `/admin-secret/`).

Confirmed by hand:
- `8017/robots.txt` -> `User-agent: *` / `Disallow: /admin-secret/`
- `8013/.git/HEAD` -> `ref: refs/heads/master` (full repo exposed; flag is in history)

## Different-wordlist pass (subtask 3)
Re-ran 8010 & 8011 with `big.txt` (~20k words) + backup/swap extensions
(`scan-80XX-big.txt`): **both empty — no new hits.** Lesson: a bigger wordlist does
NOT help here. The leaks common.txt missed are **not dictionary-discoverable**:
- 8010 (leak1) = `config.py~` editor backup "twin" (`-x` can't append `~`)
- 8011 (leak2) = a hidden API route (non-dictionary name)
- 8014 (leak5) = IDOR on `/api/users/1` (a value, not a path)
- 8018 (leak9) = HTML comments (no path)
- 8019 (leak10) = debug 500 on every path
=> wordlist scanners catch path-based leaks (listing/VCS/robots); backup-file,
hidden-route, IDOR and in-page leaks need page hints + manual work (Tasks 4/5).

## WordPress (wpscan, `web/wordpress-wpscan.txt`)
Scan via vhost `http://wordpress.chal.deti:8084` (bare IP wasn't served — name-based
vhost). `vp,vt` need a paid API token, so used `p,t,u` (inventory only).
- Core: **WordPress 7.1.3** (wpscan says "Latest, released 2026-10-06" — lab clock is
  forward-dated, so NOT genuinely old despite the challenge hint).
- Stack: **PHP 8.3.31**, Apache 2.4.67 (Debian). `X-Powered-By` leaks PHP version.
- **Multisite** enabled; external **WP-Cron** enabled; `readme.html` exposed.
- Plugin: akismet (dir 403). Main theme undetected. Users not enumerated (scan cut).
- Read: WP core is current -> the flag ("outside the web root") is a **path/misconfig
  info-disclosure**, not a core CVE. That's a Task 4 solve.

---

# Task 5 — Manual techniques (curl only)

## 1. 404 baseline (why it matters)
| Host | nonexistent path response |
|------|---------------------------|
| gunicorn (8010-8023) | `404 NOT FOUND`, `Server: gunicorn`, body **207 bytes** (Flask default) |
| 8019 (leak10) | **500**, ~1737 bytes (debug) — "everything errors" |
| Apache PHP (8081-8084) | Apache 404 page (or the 8084 proxy's fixed 90-byte error for PHP paths) |
Evidence: `web/404-baseline.txt`. **Why it matters:** every content-discovery technique
depends on being able to tell "exists" from "doesn't". If a host returns 200/500 for
*everything* (8019, and 8084's PHP proxy), naive status-code filtering is useless and you
must filter on body length/content instead (exactly what broke gobuster on 8019/8084 and
why the WP static-vs-PHP split was readable). Know the baseline first or every scan lies.

## 2. Headers — what each leaks (`web/task5-headers-methods.txt`)
| Port | Server | X-Powered-By | Set-Cookie | CSP |
|------|--------|--------------|-----------|-----|
| 3000 Juice Shop | *(hidden)* | — | — | **none** (has X-Frame/nosniff only) |
| 8000 CTFd | gunicorn | — | `session=…; HttpOnly; SameSite=Lax` | none |
| 8010-8020 leaks | gunicorn | — | — | none |
| 8081 bWAPP | Apache/2.4.7 (Ubuntu) | **PHP/5.5.9-1ubuntu4.14** | — | none |
| 8082 DVWA | Apache/2.4.25 (Debian) | — | `PHPSESSID=…` (no HttpOnly) + `security=low` | none |
| 8083 Mutillidae | Apache/2.4.7 (Ubuntu) | **PHP/5.5.9-1ubuntu4.24** | `PHPSESSID=…` (no HttpOnly) + `showhints=1` | none |
| 8084 WordPress | Apache/2.4.67 (Debian) | PHP/8.3.31 | — | none |

- **Server** leaks web server + distro; Apache `2.4.7 (Ubuntu)` is 14.04-era (EOL). gunicorn hides version.
- **X-Powered-By** is the worst offender: bWAPP/Mutillidae leak **exact PHP 5.5.9 down to the Ubuntu patch revision** (4.14 vs 4.24) — perfect for CVE matching; PHP 5.5.9 is EOL. gunicorn apps leak nothing.
- **Set-Cookie:** CTFd is done right (`HttpOnly`, `SameSite=Lax`). The PHP apps' `PHPSESSID` has **no HttpOnly** → an XSS can steal the session. DVWA's `security=low` is a client-side **difficulty cookie** (tamperable); Mutillidae's `showhints=1` similarly.
- **CSP:** **absent on every host** — zero XSS mitigation anywhere.

## 3. Methods — OPTIONS / TRACE
- **OPTIONS `Allow`:** the Flask/gunicorn apps advertise their methods (`GET, HEAD, OPTIONS`); the Apache/PHP apps and Juice Shop return no `Allow` on `/`.
- **TRACE:** **3000 (Juice Shop) answers `HTTP 200` to TRACE** — TRACE is **enabled** (Cross-Site Tracing / XST surface; should be `TraceEnable off`). Every other host refuses it: gunicorn → 405, CTFd → 404, Apache PHP → 405 (modern Apache disables TRACE by default). So Juice Shop is the lone outlier.

## 4. JavaScript — constants the client carries that the server never advertises
The API host is **leak5 (:8014, "Directory service")**. Its client script
`/static/app.js` (not linked anywhere; found by probing static paths) contains:
```js
// profile viewer
const ADMIN_PROFILE_ID = 7;
// loadProfile(ADMIN_PROFILE_ID);
```
The server never tells you *which* user is the admin — `/api/users/<id>` just returns
name/email. The **client leaks it**: `ADMIN_PROFILE_ID = 7`. That constant (plus the
commented-out `loadProfile`) points you straight at id 7, which is exactly where the
over-serialized flag lives (leak5). Lesson: client-side JS carries business logic /
identifiers the API itself withholds — always read it.

## 5. Tokens — two formats, one readable
Two session artifacts captured:
| Host | Artifact | Format | Readable without key? |
|------|----------|--------|-----------------------|
| leak6 (:8015) | `token` (body) | **JWT** `base64url.base64url.hmac` | **YES** — payload is just base64url |
| CTFd (:8000) | `session` cookie | `<uuid>.<base64 HMAC>` (Flask signed session) | **NO** — opaque id + signature |
| DVWA/Mutillidae | `PHPSESSID` | opaque random id | NO (server-side session) |

- The **JWT (leak6)** reads without any key — base64url-decode the middle segment and
  you get `{"sub":"guest","role":"user","feature_flags":{"show_admin":true},
  "flag":"flag{…}"}`. Reading it gave the role, a hidden feature flag, **and the flag**.
- The **CTFd/Flask session cookie** and **PHPSESSID** are opaque — signed or random
  server-side references that reveal nothing without the server's secret.
- Takeaway: a signed-but-readable token (JWT) is integrity-protected, **not**
  confidential — anything in its payload is exposed. Opaque session ids leak nothing.
  (This is the whole leak6 bug: secrets in a readable JWT claim.)

## 6. Fuzz by hand — manual vs scanner (host: leak2 :8011)
Hand-picked 10 paths from intuition (no wordlist), baseline = 404:
```
200  /api/ping      <- hit
200  /debug/env     <- hit (the flag route)
404  /debug/vars /debug/config /api/status /api/health /metrics /admin /internal /console
```
- **What hand-fuzzing found that the scanner missed:** `/debug/env` (and `/api/ping`).
  Neither is in `common.txt` or `big.txt` — both gobuster runs on 8011 returned
  **nothing**. `/debug/env` is reached only by *reasoning* about conventions
  (a "debug" prefix + an "env" dump), not by a dictionary. This is the whole leak2 solve.
- **What the scanner found that hand-fuzzing would miss:** on the path-based challenges,
  gobuster systematically caught dictionary entries you would not exhaustively hand-type
  — `/.git/HEAD` (leak4), `/robots.txt` (leak8), `/oracle` (leak7), `/public/` (leak3),
  and backup extensions. Breadth over a known namespace is the scanner's strength.
- **Conclusion:** scanners = breadth over a *known* dictionary; manual = depth via
  reasoning about the app's *own* conventions (prefixes, debug/ops routes, non-dictionary
  names). leak1 (`config.py~` backup), leak2 (`/debug/env`) and leak5 (IDOR value, not a
  path) are all invisible to wordlists — you need both techniques.

**Task 5 complete** — evidence in `web/task5-headers-methods.txt`, `web/404-baseline.txt`,
`web/app-versions.txt`, and the leak writeups.
