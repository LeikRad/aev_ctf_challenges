# AEV Infoleak — Progress TODO

Legend: `[x]` done · `[~]` partial · `[ ]` not started.
Evidence paths are relative to `infoleak/`.

---

## Task 1 — Host discovery and service mapping  ✅ COMPLETE
- [x] How many hosts / which answer / what each is → 4 hosts; `.1` gw+DNS+Proxmox, `.2`/`.4` Proxmox nodes, `.72` challenge host — `10.110.3.72/scan-discovery.txt`, `scan-infra.txt`, `report.md §2`
- [x] Port → service → challenge map for `.72`, cross-checked vs DNS + CTFd — `report.md §3`, `10.110.3.72/notes.md`
- [x] Find the UDP service, solve + submit flag → SNMP 8024, `flag{3cad557d9709a6a658ae582ce33ab216}` — `10.110.3.72/snmp-walk.txt`, `report.md §4`
- [x] DNS: confirm `*.chal.deti` wildcard, enumerate names, note implications — `report.md §5`
- [x] Fingerprint stack / shared Server banners — `report.md §6`, `10.110.3.72/web/web-map.txt`
- [x] Short discovery report — `report.md`

---

## Task 2 — Version and CVE enumeration  ~ PARTIAL
- [x] Enumerate software versions for every service (`nmap -sV`) — `10.110.3.72/scan-versions.txt`
- [x] `nmap -sV --script vulners` + triage real vs noise — `vulners.txt`; triage in `notes.md` Task 2 (feed is lab-seeded/forward-dated, banner-match = noise)
- [~] Stock web apps versions + CVEs — juiceshop 20.2.0, DVWA v1.10, Mutillidae 2.6.62/PHP 5.5.9, bWAPP ~2.2; **WordPress core still TBD → wpscan (Task 3)** — `web/app-versions.txt`
- [x] Critical CVEs + realistic recommendations — EOL PHP 5.5.9 + Apache 2.4.7; WP core; see `notes.md` Task 2
- [x] Write conclusions in notes, backed by logs — `notes.md` Task 2 section

---

## Task 3 — Web content discovery  ✅ COMPLETE
- [x] 404 baseline — clean 404/207b on gunicorn hosts; 8019 = 500-on-everything — `web/404-baseline.txt`
- [x] Content scan every `leak*` + `notes1`, one file per host — `web/scan-80XX-gobuster.txt`
- [x] Classify each hit (dir listing 8012, .git+source 8013, robots 8017, oracle 8016, auth 8015/8020) — `notes.md` Task 3
- [x] Different wordlist (big.txt on 8010/8011) — no new hits; backup/hidden-route/IDOR not dictionary-discoverable — `web/scan-80XX-big.txt`
- [x] WordPress wpscan — core 7.1.3, PHP 8.3.31, multisite, WP-Cron, readme exposed, akismet — `web/wordpress-wpscan.txt` (vp/vt need paid token; core current → flag is path/misconfig)

---

## Task 4 — The infoleak suite (solve + submit each)  ~ PARTIAL
- [x] leak9 (:8018) — HTML comment `flag{7ae72615...}` — `challenges/infoleak/leak9/writeup.md`
- [x] leak10 (:8019) — Flask debug traceback local `flag{a955c19f...}` — `challenges/infoleak/leak10/writeup.md`
- [x] leak8 (:8017) — robots.txt → /admin-secret/ → `flag{70d7874e...}` — `challenges/infoleak/leak8/writeup.md` (no CTFd submit field)
- [x] leak3 (:8012) — dir listing /public/ → flag.txt → `flag{ecb15c4e...}` — `challenges/infoleak/leak3/writeup.md`
- [x] leak1 (:8010) — /static/config.py.bak → `flag{eb2ccf88...}` — `challenges/infoleak/leak1/writeup.md`
- [x] leak2 (:8011) — prefix-fuzzed /debug/env env dump → `flag{35232b6a...}` — `challenges/infoleak/leak2/writeup.md`
- [x] leak4 (:8013) — git-dumped .git, flag in deleted commit → `flag{g1t_h1story_l34ks}` — `challenges/infoleak/leak4/writeup.md`
- [x] leak6 (:8015) — decoded JWT payload claim → `flag{e13f1176...}` — `challenges/infoleak/leak6/writeup.md`
- [x] leak5 (:8014) — /api/users/7?verbose=1 over-serializes flag → `flag{8e23460c...}` — `challenges/infoleak/leak5/writeup.md`
- [x] leak7 (:8016) — scripted prefix oracle (1457 reqs) → `flag{362222c4...}` — `challenges/infoleak/leak7/writeup.md`
- [x] snmp1 (:8024/udp) — walked tree, flag from private enterprise OID — `challenges/network/snmp1/writeup.md`, `10.110.3.72/snmp-walk.txt`
  - [x] follow-up: MIB-II vs enterprise split + on-demand node = exec surface — `challenges/network/snmp1/writeup.md`
- [x] notes1 (:8020) — guest/guest123, IDOR on /note/3 (admin) → `flag{idor_local_verify}` — `challenges/infoleak/notes1/writeup.md`

### Optional challenges (outside infoleak suite)
- [x] True Names (crypto) — SOLVED → `AEV{th3_sky_4b0v3_th3_p0rt}`. The ":9001" prompt
      was a DECOY (pure echo). "The node you came in through" = the CTFd server itself
      (`ctfd.chal.deti`); the trace was a Vigenère ciphertext hidden in a `data-trace`
      attribute of the landing-page HTML (`WMI{ml3_jws_4u0z3_pp3_c0kx}`). Key = the
      Tessier-Ashpool AI name **WINTERMUTE**; plaintext = Neuromancer's opening line.
      Solvable fully offline (no remote session). Full writeup — `challenges/crypto/true-names/writeup.md`
- [~] wordpress (:8084) — VECTOR IDENTIFIED: CVE-2026-63030 "wp2shell" (+CVE-2026-60137),
      unauth core RCE via /wp-json/batch/v1 route-confusion + WP_Query SQLi. PoC ready
      (github.com/Icex0/wp2shell-poc): check → read users (admin+hash) → shell (pass-hash)
      → cat flag outside webroot. Near-stock WP (only akismet + default themes), so it's
      the CORE CVE. BLOCKED: PHP backend DOWN ("No route to host", 5/5 + PoC check fails);
      needs a PHP up-window. Report outage; finish when restored. Full writeup —
      `challenges/web/wordpress/writeup.md`

---

## Task 5 — Manual techniques (curl + browser only)  ✅ COMPLETE
All written up in `notes.md` Task 5; evidence `web/task5-headers-methods.txt`.
- [x] 404 baseline (gunicorn 207b / 8019 500 / Apache) + why it matters
- [x] Header comparison: X-Powered-By leaks exact PHP 5.5.9+Ubuntu patch (bWAPP/Mutillidae); no CSP anywhere; PHPSESSID no HttpOnly; CTFd cookie hardened
- [x] Methods: Flask apps advertise Allow; **Juice Shop :3000 answers TRACE 200 (XST)**, all others 405/404
- [x] API host JS: leak5 `/static/app.js` leaks `ADMIN_PROFILE_ID = 7`
- [x] Tokens: leak6 JWT readable (base64url → role/flag) vs CTFd/PHPSESSID opaque
- [x] Hand-fuzz: leak2 — manual found `/debug/env` (flag route) that common.txt+big.txt both missed

---

## Task 6 — Hardening report  ✅ COMPLETE
- [x] Per-host/per-class recommendations — `10.110.3.72/hardening.md`
- [x] Ranked by (impact, effort) + "do first" = deployment-hygiene pass — `hardening.md`

---

## Deliverable (PTES)  ✅ COMPLETE
- [x] Discovery report for `.72` — `report.md`
- [x] Per-target working notes — `10.110.3.72/notes.md`
- [x] Findings per leak class (evidence + severity + recommendation) — `hardening.md` + 14 writeups
- [x] Automated-vs-manual comparison — `notes.md` Task 5.6
- [x] Open questions / undetermined — wordpress (backend outage) in writeups
### Remaining nice-to-haves (optional polish)
- [x] **Top-level exec summary** — `summary.md` (scope + method; 13 flags captured;
      wordpress blocked by outage; xss1-3 pending; headline risks; do-first = hygiene pass)
- [x] **Formal CVE table** — `report.md` §9 (software | version | port | CVE | CVSS |
      exploitability), with the lab-seeded/forward-dated vulners caveat
      Note: vulners feed is lab-seeded/forward-dated → version-match = triage, not proof.

---

## Anomalies logged (report to organizers per RoE)
- [x] 8084 (wordpress) returned `Failed to daemonise / No route to host (113)` — broken backend
- [x] SNMP 8024 replies with SET-PDU (breaks standard snmpwalk)
- [x] `leak8` present as a challenge (:8017) though it was missing from the scoreboard grid at first view — re-confirm
- [x] Stock apps identified: 3000 juiceshop, 8081 bWAPP, 8082 DVWA v1.10, 8083 Mutillidae, 8084 wordpress — `web/stock-apps.txt`
- [x] 8021-8023 (Lab recipes / Bench log / Team card) = the XSS challenges xss1/xss2/xss3 (web); exact xssN↔port + release status TBD (may be future/unreleased) — NOT filler

---

## Task 7 — New board (SQLI / INJ / AUTH categories)  ~ IN PROGRESS
Released after infoleak/web/network/crypto. Writeups + `solve.py` per challenge under `challenges/<cat>/<name>/`.
Progress as of 2026-11-11: **33/36 solved** (3 left, all DOWN: Catalogo, StockEye, ToolDesk). **SQLI COMPLETE (8/8).**. **AUTH category COMPLETE (14/14).**

### AUTH (14/14 done ✅)
- [x] NetGuard Router (:8060) — CWE-1392/521 default Basic-Auth creds `admin:admin123` — `challenges/auth/NetGuard_Router/`
- [x] Harbor Wiki (:8061) — CWE-293 Referer-trusted internal page — `challenges/auth/Harbor_Wiki/`
- [x] QuickShip Tracker (:8062) — CWE-598 sid leaked in GET link via review — `challenges/auth/QuickShip_Tracker/`
- [x] ExpenseFlow (:8063) — CWE-602 unsigned `role` cookie → `role=manager` — `challenges/auth/ExpenseFlow/`
- [x] PeopleFirst HR (:8069) — CWE-204 user enum (`emp_id`) + default pw `admin123` — `challenges/auth/PeopleFirst_HR/`
- [x] Cornerstone CMS (:8071) — CWE-257/522 base64 pw in exposed `/export/*.sql.bak` — `challenges/auth/Cornerstone_CMS/`
- [x] FernBank Online (:8073) — CWE-613 session not expired on logout; replay leaked sid — `challenges/auth/FernBank_Online/`
- [x] Alma Portal (:8064) — CWE-384 fixation via helpdesk bot (submitter session) — `challenges/auth/Alma_Portal/`
- [x] Brightleaf (:8065) — CWE-384 cross-host fixation, attacker-chosen sid — `challenges/auth/Brightleaf/`
- [x] ConnectAPI Partner Gateway (:8066) — CWE-347 JWT `alg:none` → partner=admin — `challenges/auth/ConnectAPI_Partner_Gateway/`
- [x] PocketBank Lite (:8067) — CWE-327 JWT HS256 4-digit key `0468`, forge role=admin → `/accounts/admin` — `challenges/auth/PocketBank_Lite/`
- [x] DeskHero Helpdesk (:8068) — CWE-330/331 token=`sha1("admin:<second>")`, enumerate mint second — `challenges/auth/DeskHero_Helpdesk/`
- [x] InboxNow Webmail (:8070) — CWE-640/330 reset token=`sha256("reset:<name>")[:20]`, take over postmaster — `challenges/auth/InboxNow_Webmail/`
- [x] RemoteLink VPN (:8072) — CWE-307 no rate-limit, dict brute `vpnuser:qwerty` — `challenges/auth/RemoteLink_VPN/`

### SQLI (8/8 done ✅)
- [x] Staff Portal (100) — `challenges/sqli/Staff_Portal/`
- [x] TechBazaar Search (200) — `challenges/sqli/TechBazaar_Search/`
- [x] PhotoVault (:8032) — CWE-89 UNION SQLi (SQLite), 4 cols, flag in `vault.secret` — `challenges/sqli/PhotoVault/`
- [x] DropLite (:8033) — CWE-89 blind/boolean SQLi, count-flip oracle, flag=`quarterly-keys.txt` content (274 reqs) — `challenges/sqli/DropLite/`
- [x] The Daily Byte (:8034) — CWE-89 blind content/marker SQLi, UNION row gated by WHERE, flag in `vault.secret` (274 reqs) — `challenges/sqli/The_Daily_Byte/`
- [x] Guestbook (:8035) — CWE-89 blind SQLi on INSERT (**MariaDB**), error-flash boolean oracle, flag in `vault.secret` (~274 reqs) — `challenges/sqli/Guestbook/`
- [x] Linkly (:8036) — CWE-89 OOB SQLi via server-side link fetch, exfil to internet collector, flag in `vault.secret` — `challenges/sqli/Linkly/`
- [x] TransferOps Console (:8037) — CWE-89 OOB file-write, export hidden `vault` table to served `/reports/vault.csv` — `challenges/sqli/TransferOps_Console/`

### INJ (8/14 done; Catalogo+StockEye down)
- [x] LibraryNet (100) — `challenges/inj/LibraryNet/`
- [x] ShelfTag (:8041) — CWE-78 OS command injection, blacklist misses newline (`%0A`), `cat /flag/flag` — `challenges/inj/ShelfTag/`
- [x] OpsBoard (:8042) — CWE-94 Jinja2 SSTI RCE, `lipsum.__globals__.os.popen` → `cat /flag/flag` — `challenges/inj/OpsBoard/`
- [~] Catalogo (:8043) — CWE-611 XXE (appears DOWN 2026-11-11, retry) — plan: `<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///flag/flag">]>` + `&xxe;` in `<title>` — `challenges/inj/Catalogo/`
- [x] NightPack (:8044) — CWE-78 OS cmd injection via `sh -c` arg slot, `catalog;cat /flag/flag` — `challenges/inj/NightPack/`
- [x] DeskOne (:8046) — CWE-78 cmd substitution `$(cat /flag/flag)` in requester, output on `/log` — `challenges/inj/DeskOne/`
- [x] CardCraft (:8045) — CWE-94 EJS (Node) SSTI RCE, `process.getBuiltinModule('child_process').execSync` — `challenges/inj/CardCraft/`
- [~] StockEye (:8047) — CWE-78 glob bypass (appears DOWN 2026-11-11, retry) — plan: `ls/cat <path>`, blacklist blocks literal `/flag/flag` but not `*`; use `path=/f*/f*` → shell globs to `/flag/flag` — `challenges/inj/StockEye/`
- [x] PicLink (:8048) — CWE-918 SSRF via `url=file:///flag/flag` in image proxy — `challenges/inj/PicLink/`
- [x] LogWarden (:8050) — CWE-78 second-order cmd injection, store `/ && cat /flag/flag` in logdir then `/ship` — `challenges/inj/LogWarden/`
- [x] GateKeeper (:8053) — CWE-78 WAF bypass, 2 doors: double-encode (`%253B`) + HPP (dup `cmd`) — `challenges/inj/GateKeeper/`
- [~] ToolDesk (:????) — appears DOWN 2026-11-11, retry — `challenges/inj/ToolDesk/`
- [x] SessionVault (:8051) — CWE-94 Python pickle deserialization, `__reduce__` → `open('/flag/flag')`, preview reads it — `challenges/inj/SessionVault/`
- [x] FaaSDeck (:8052) — CWE-78 allowlist ignores file arg; deploy function `body=head /flag/flag` (cat blocked) + invoke (exec door arg-filtered) — `challenges/inj/FaaSDeck/`
