# AEV Infoleak Lab — Executive Summary

**Engagement:** Internal footprinting + information-disclosure assessment of the DETI
`*.chal.deti` lab — host `10.110.3.72`, segment `10.110.3.0/24`.
**Method:** nmap discovery/version scans, DNS enumeration, gobuster + wpscan content
discovery, manual curl/header/token analysis, and a custom scapy SNMP walker. No
exploitation beyond challenge scope; management plane (Proxmox :3128) left untouched.

## Results
- **13 flags captured:** leak1–leak10 (web info-disclosure), snmp1 (UDP SNMP), notes1
  (IDOR), and True Names (crypto).
- **1 challenge blocked:** wordpress (:8084) — unauth RCE vector identified
  (CVE-2026-63030), blocked by a backend outage (`No route to host`, 5/5).
- **3 challenges pending/unreleased:** xss1/xss2/xss3 on 8021–8023 (live services, not
  yet shown on the scoreboard).

## Headline risks (by severity)
| Risk | Where | Severity |
|------|-------|----------|
| Unauthenticated core RCE (CVE-2026-63030 "wp2shell" + CVE-2026-60137 SQLi) | WordPress :8084 | **Critical** |
| EOL software, no upstream patches (PHP 5.5.9; Apache 2.4.7 / Ubuntu 14.04) | bWAPP :8081, Mutillidae :8083 | High |
| Pervasive info-disclosure — debug traces, `.git`, backup files, `/debug/env`, IDOR, secrets in JWT | Flask fleet 8010–8020 | High (class) |
| SNMP world-readable `public` + exec/extend command surface | snmp1 :8024/udp | High |
| No CSP + non-HttpOnly cookies, with intended XSS targets on the box | all web hosts; xss1–3 | Medium→High |

## Do first
**Deployment-hygiene pass** — debug off, generic error handler, and a deploy that ships
no `.git` / backup files / debug routes in the web root. Near-zero effort; closes
leak1, leak2, leak4, leak9, leak10 in one move. Then: patch the WordPress RCE (highest
severity, single host), rotate SNMP off `public` and drop `exec`/`extend`, and apply the
cheap header hardening (banners, CSP, cookie flags, `TraceEnable off`) everywhere.

*No such thing as perfect security* — these are deliberately vulnerable training targets;
the realistic posture is: patch the one critical RCE, do the cheap config hardening
across the board, and network-isolate the EOL stacks that can't be upgraded.

## Where the detail lives
- Discovery + service map + formal CVE table → `report.md`
- Per-class findings, evidence, ranked fixes → `10.110.3.72/hardening.md`
- Per-challenge writeups → `challenges/<category>/<name>/` (writeup.md + scripts)
- Working notes + raw scan outputs → `10.110.3.72/`
