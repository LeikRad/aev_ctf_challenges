# Hardening Report — 10.110.3.72 (DETI vulnerability lab)

**Task 6 deliverable.** Recommendations for the owner of every service assessed,
grouped by finding class, each with evidence, severity, and a fix. Ranked by
(impact, effort) at the end, with the single action to do first.

Severity scale: Critical / High / Medium / Low (lab context — these are deliberately
vulnerable training targets, so severities describe the *class* of weakness).

---

## A. Information-disclosure suite (leak1–10) — the gunicorn/Flask apps

| # | Finding | Evidence | Severity | Recommendation |
|---|---------|----------|----------|----------------|
| leak9 | Secret in HTML comment | `<!--FLAG: …-->` in page source | Medium | Strip comments from production templates; CI grep for `FLAG`/`TODO`/`DEBUG` in built HTML |
| leak10 | Flask **debug mode** → stack trace leaks frame locals | `/crash` traceback shows `secret = 'flag{…}'` | **High** | `debug=False`/`FLASK_DEBUG=0`; register a generic 500 handler that returns no trace; keep secrets out of view-locals |
| leak3 | **Directory listing** (autoindex) | `/public/` lists `flag.txt` | Medium | Disable autoindex (`Options -Indexes` / `autoindex off`); don't store files under a web-served dir |
| leak1 | **Backup file** in web root | `/static/config.py.bak` leaks `FLAG`+API URL | High | Keep configs/secrets out of the web root; block `~ .bak .swp .old .save` at the server; deploy an explicit asset allow-list |
| leak2 | **Unauthenticated debug route** dumping env | `/debug/env` returns `os.environ` incl. secrets | **High** | Remove debug/introspection routes from prod; authenticate ops endpoints; never serialize `environ` to clients |
| leak4 | **Exposed `.git`** — secret in history | `/.git/` live; flag in a deleted commit | **High** | Never deploy `.git` (block `location ~ /\.git`); rotate any ever-committed secret and purge history (filter-repo/BFG); add gitleaks to CI |
| leak8 | `robots.txt` used as access control | `Disallow: /admin-secret/` → flag | Medium | Put real authn/authz on sensitive paths; `robots.txt` is an index, not a gate |
| leak5 | **Excessive data exposure / IDOR** | `/api/users/7?verbose=1` serializes a secret field | High | Serialize via an explicit field allow-list (DTO/schema), never the raw model; keep secrets off the user object |
| leak6 | **Secret in a (readable) JWT claim** | base64url payload carries `flag` | High | Never store secrets/PII in a JWT; signed ≠ confidential. Use opaque session ids or encrypted tokens (JWE); drop `feature_flags.show_admin` leak |
| leak7 | **Prefix oracle** leaks secret char-by-char | `/oracle?prefix=` yes/403 | Medium | No partial-match checks on secrets; constant-time full comparison only; rate-limit + lockout to stop extraction |
| notes1 | **Broken object-level authz (IDOR)** | guest reads `/note/3` (owner=admin) | **High** | Enforce `note.owner == current_user` on every access; 403/404 otherwise; UI omission is not access control |

**Cross-cutting:** this whole category is *excessive trust in the client / forgotten
developer artifacts*. A single deployment-hygiene pass (debug off, no backups/VCS/debug
routes in the web root, generic errors) neutralizes most of it.

---

## B. SNMP (snmp1) — UDP 8024

| Finding | Evidence | Severity | Recommendation |
|---------|----------|----------|----------------|
| World-readable `public` community exposes a private OID secret | flag at `1.3.6.1.4.1.99999.1.1.0` | High | Rotate the community off `public`; restrict SNMP to management hosts/ACL; prefer **SNMPv3** (auth+priv); never place secrets in MIB values |
| On-demand/script-backed node = command-execution surface | private `.99999` node generated on query (net-snmp `exec`/`extend`) | High | Remove/sandbox `exec`/`extend`/`pass` directives; ensure no writable community can reach `NET-SNMP-EXTEND-MIB` |
| Non-conformant agent (replies with SET-PDU) | breaks standard `snmpwalk` | Low | Fix the agent to return GET-RESPONSE; report as a defect |

---

## C. Stack & version disclosure (Tasks 2 & 5)

| Finding | Evidence | Severity | Recommendation |
|---------|----------|----------|----------------|
| **X-Powered-By leaks exact PHP version + distro patch** | `PHP/5.5.9-1ubuntu4.14` (bWAPP), `…4.24` (Mutillidae) | Medium | `expose_php = Off`; strip `X-Powered-By` at the proxy |
| **Server banner leaks web server + OS** | `Apache/2.4.7 (Ubuntu)` (EOL 14.04), `2.4.25`, `2.4.67` | Medium | `ServerTokens Prod`, `ServerSignature Off` |
| **EOL software** | PHP 5.5.9 (EOL 2016), Apache 2.4.7/Ubuntu 14.04 | High | Upgrade or retire; isolate to a lab-only network if kept |
| **No Content-Security-Policy on any host** | all 10 hosts | Medium | Add a restrictive CSP (big XSS mitigation, esp. for the PHP apps) |
| **Session cookies without HttpOnly** | DVWA/Mutillidae `PHPSESSID` | Medium | Set `HttpOnly; Secure; SameSite` (CTFd already does this correctly) |
| **TRACE enabled** | Juice Shop :3000 answers `HTTP 200` | Low | `TraceEnable off` (Cross-Site Tracing) |
| Tamperable client-side state cookie | DVWA `security=low` | Low | Keep trust decisions server-side |

### C.1 Formal CVE / version table

**Caveat:** the `nmap --script vulners` feed (`vulners.txt`) is **lab-seeded and
forward-dated** (`CVE-2026-*`) and matches on version banners only — it cannot tell a
backported-but-patched distro build from a vulnerable one. Rows below are **triage, not
proof**. Actionable items = the EOL components and the WordPress core RCE; the four stock
apps are vulnerable *by design at the app layer*, not primarily via server CVEs.

| Software | Version | Port(s) | CVE(s) | CVSS | Exploitability in lab |
|----------|---------|---------|--------|------|-----------------------|
| WordPress core | reports 7.1.3; actually 6.9.x/7.0.x | 8084 | CVE-2026-63030 "wp2shell" (+ CVE-2026-60137 SQLi) | 9.8 | **Unauth RCE.** PoC staged; blocked by backend outage |
| PHP | 5.5.9 (EOL 2016) | 8081, 8083 | CVE-2016-5385 (httpoxy) + many | ~5–8 | Unsupported — no vendor patches; several config-gated |
| Apache httpd | 2.4.7 (Ubuntu 14.04, EOL) | 8081, 8083 | CVE-2014-0226, CVE-2019-0211 | 6.8 / 7.8 | Large surface but mostly local priv-esc / config-gated |
| Apache httpd | 2.4.25 (Debian) | 8082 | CVE-2017-9798 (Optionsbleed), CVE-2017-7679 | 5.3 / 7.5 | Config-dependent — verify module/OPTIONS first |
| Apache httpd | 2.4.67 (Debian, ~2023) | 8084 | few / minor | Low | Low — recent branch, smallest surface |
| OpenSSH | 10.0p2 | 22 (infra) | — | — | Out of scope; 2026-dated feed = triage only |
| Juice Shop / DVWA v1.10 / bWAPP / Mutillidae | — | 3000 / 8082 / 8081 / 8083 | n/a (intentional) | n/a | App-layer by design, not CVE-driven |

**Read:** only two rows are "patch now" — **WordPress** (Critical, pre-auth RCE) and the
**EOL PHP/Apache** stacks (High, because unsupported regardless of CVSS). The rest is
config-gated (verify first) or intentionally vulnerable at the app layer.

---

## D. WordPress (wordpress) — :8084

| Finding | Evidence | Severity | Recommendation |
|---------|----------|----------|----------------|
| **Unauthenticated core RCE (CVE-2026-63030 "wp2shell"** + CVE-2026-60137 SQLi) | `/wp-json/batch/v1` route confusion; near-stock WP, vulnerable core | **Critical** | Patch WordPress core to **6.9.5 / 7.0.2+**; WAF-filter the batch endpoint as interim; least-privilege the DB user |
| Version misrepresentation | reports 7.1.3 while actually a vulnerable 6.9.x/7.0.x | Low | n/a (attacker-relevant note) |
| Availability — PHP backend down | fixed 90-byte `No route to host` for all PHP paths | — | Operational: restart/stabilise the backend container; monitor/alert |

---

## E. Infrastructure / scope notes

- **Proxmox REST API (:3128)** exposed on all three cluster nodes — management plane;
  restrict to admin network (not probed, per RoE).
- **True Names** (SOLVED) — the flag was a Vigenère ciphertext embedded client-side in a
  `data-trace` attribute of the CTFd landing-page HTML (`ctfd.chal.deti`), recoverable by
  anyone who reads page source. This is itself an **info-disclosure** finding: a
  secret shipped in client-delivered markup, "protected" only by a classical name-keyed
  cipher whose key (`WINTERMUTE`) is telegraphed by the page's own Neuromancer theming.
  Recommendation: never embed secrets (even encrypted) in client-side HTML/attributes;
  classical ciphers provide no confidentiality against a reader of the source.

---

## Ranked recommendations (impact × effort)

| Rank | Action | Impact | Effort | Why |
|------|--------|--------|--------|-----|
| 1 | **Deployment hygiene pass:** debug off + generic errors; remove `.git`, backup files, and debug/env routes from the web root | High | Low | Kills leak1/2/4/9/10 at once — most of the infoleak suite — with config + a clean deploy |
| 2 | Suppress banners/version headers (`ServerTokens Prod`, `expose_php Off`, strip `X-Powered-By`) | Med | Low | Stops version→CVE mapping across all Apache/PHP hosts |
| 3 | Disable directory listing (`Options -Indexes`) | Med | Low | Fixes leak3; prevents file enumeration |
| 4 | Rotate SNMP community off `public` + restrict/disable; remove `exec`/`extend` | High | Low | Fixes snmp1 + removes a command-exec surface |
| 5 | **Patch WordPress core (CVE-2026-63030)** | Critical | Med | Removes a pre-auth RCE — highest severity, but needs an upgrade/rebuild |
| 6 | Retire EOL PHP 5.5.9 / Apache 2.4.7 | High | Med/High | Unsupported; no upstream fixes |
| 7 | Fix IDOR / broken object authz (leak5, notes1) | High | Med | Code change: server-side ownership checks + field allow-lists |
| 8 | Redesign tokens — no secrets in JWT claims (leak6) | Med | Med | Code change: opaque/encrypted tokens |
| 9 | Add CSP, HttpOnly cookies, `TraceEnable off` | Med | Low | Hardening headers across the board |

### What I would do first
**The deployment-hygiene pass (rank 1).** A debug flag flipped to off, a generic error
handler, and a deploy that doesn't ship `.git` / backup files / debug routes is nearly
zero effort and single-handedly closes **leak1, leak2, leak4, leak9, leak10** — the bulk
of the exposed surface. The WordPress RCE (rank 5) is the highest *severity* and must be
patched, but it's a single host needing an upgrade; the hygiene pass is the best
impact-per-effort and removes an entire class of leaks across many services at once.

*No such thing as perfect security* — these are deliberately vulnerable training apps, so
the realistic posture is: patch the one critical RCE, do the cheap config hardening
everywhere, and network-isolate the EOL stacks that can't be upgraded.
