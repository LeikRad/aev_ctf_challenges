# Internal Footprinting — Discovery Report

**Engagement:** AEV lab — Information Gathering / Internal Footprinting (OWASP PTES)
**Scope:** `10.110.3.0/24`, in particular `10.110.3.72` and every `*.chal.deti`
**Date:** 2026-10-13
**Author:** s14
**Rules honoured:** `-T3` or lower for version scans, small UDP port sets, low
content-scan parallelism, no exploitation beyond what a challenge asked, no login
spraying, infra management plane (Proxmox :3128) left untouched.

---

## 1. Executive summary

The `10.110.3.0/24` segment contains **4 live hosts**: a Proxmox virtualization
cluster of three nodes (`.1`, `.2`, `.4`) and a single **challenge host** (`.72`).
All CTF challenges run on `.72` as **name + port virtual hosts** behind a wildcard
DNS record (`*.chal.deti` → `.72`). The host exposes two clear application stacks —
a uniform **Python/Flask-on-gunicorn** fleet (CTFd + the info-leak challenges) and a
small, heterogeneous set of **Apache/PHP** apps of widely varying age. One UDP
service (SNMP on a non-standard port) was identified and its challenge solved. A
port scan reveals **more running services than the CTFd scoreboard publishes**,
underlining why scan results must be cross-checked against the authoritative
challenge list.

**Challenge solved during discovery:** `snmp1` →
`flag{3cad557d9709a6a658ae582ce33ab216}`.

---

## 2. Hosts (Task 1)

| IP | Up | Role | Evidence |
|----|----|------|----------|
| 10.110.3.1 | yes | Gateway + DNS + Proxmox node | dnsmasq 2.91 :53, Proxmox VE API :3128, rpcbind :111 |
| 10.110.3.2 | yes | Proxmox node (infra) | Proxmox VE API :3128, rpcbind :111 |
| 10.110.3.4 | yes | Proxmox node (infra) | Proxmox VE API :3128, rpcbind :111 |
| 10.110.3.72 | yes | **Challenge host** | all `*.chal.deti`, many web + 1 UDP service |

Method: `nmap -sn 10.110.3.0/24` (discovery) then
`nmap -sV -T3` against each host. The three infra nodes are near-identical
(OpenSSH 10.0p2 Debian, rpcbind, Proxmox REST API) — a standard Proxmox cluster
hosting the challenge VM/containers. Only `.72` is in-scope as a target; `.1/.2/.4`
are plumbing and the Proxmox API on :3128 is a management plane we deliberately did
not probe.

---

## 3. Service & challenge map for 10.110.3.72 (Task 2)

Full TCP (`-p-`) + version scan, titles via curl, bindings confirmed against each
CTFd challenge's description (the `http://<name>.chal.deti:<port>` line).

| Port | Proto | Stack | CTFd challenge | Notes |
|------|-------|-------|----------------|-------|
| 22 | tcp | OpenSSH 10.0p2 | — | infra |
| 3000 | tcp | Node | *(none)* | OWASP Juice Shop — decoy/extra |
| 8000 | tcp | gunicorn | *(platform)* | CTFd scoreboard ("AEV") |
| 8010 | tcp | gunicorn | leak1 | editor backup file |
| 8011 | tcp | gunicorn | leak2 | `/status` disclosure |
| 8012 | tcp | gunicorn | leak3 | directory listing |
| 8013 | tcp | gunicorn | leak4 | git history / old pages |
| 8014 | tcp | gunicorn | leak5 | IDOR / user enum |
| 8015 | tcp | gunicorn | leak6 | JWT token disclosure |
| 8016 | tcp | gunicorn | leak7 | boolean oracle |
| 8017 | tcp | gunicorn | leak8 | robots.txt disclosure |
| 8018 | tcp | gunicorn | leak9 ✅ | HTML comments |
| 8019 | tcp | gunicorn | leak10 ✅ | error/stack trace |
| 8020 | tcp | gunicorn | notes1 (web) | access-model leak; guest account |
| 8021 | tcp | gunicorn | xss1/2/3 (TBD) | "Lab recipes" — XSS challenge target (web); exact xssN↔port TBD |
| 8022 | tcp | gunicorn | xss1/2/3 (TBD) | "Bench log" — XSS challenge target (web); exact xssN↔port TBD |
| 8023 | tcp | gunicorn | xss1/2/3 (TBD) | "Team card" — XSS challenge target (web); exact xssN↔port TBD |
| 8081 | tcp | Apache 2.4.7 (Ubuntu) | bWAPP (stock app) | `Login` title confirms bWAPP |
| 8082 | tcp | Apache 2.4.25 (Debian) | DVWA v1.10 (stock app) | version leaked in `<title>` |
| 8083 | tcp | Apache 2.4.7 (Ubuntu) | Mutillidae (stock app) | confirmed in page body |
| 8084 | tcp | Apache 2.4.67 (Debian) | wordpress | outdated WP; flag outside web root ⚠️ |
| 3000 | tcp | Node | Juice Shop (stock app) | OWASP Juice Shop |
| 8024 | udp | SNMP | snmp1 ✅ | solved — see §4 |
| 9001 | tcp | custom socket | True Names ✅ | prompt is a DECOY; flag was a Vigenère ciphertext hidden in the CTFd landing-page HTML, key `WINTERMUTE` (writeup: `challenges/crypto/true-names/writeup.md`) |

**Cross-check insight:** nearly every running service maps to either a challenge or
a named stock app. The INFOLEAK suite is `leak1–leak10` (8010–8019); `notes1` is the
web-category challenge on 8020; the five **stock vulnerable apps** named in Task 2 —
Juice Shop (3000), bWAPP (8081), DVWA v1.10 (8082), Mutillidae (8083), WordPress
(8084) — are the CVE-enumeration targets (also released as named CTFd challenges used in
later exercises). **8021–8023** ("Lab recipes", "Bench log", "Team card") are the **XSS
challenges xss1/xss2/xss3** (web category) — their app titles are classic reflected/
stored-XSS surfaces; exact xssN↔port assignment and release status are TBD (may not be
live yet). Takeaway: a port list over-reports *and* under-maps — cross-check every
service against the full CTFd challenge list (including unreleased/future ones), not just
the scoreboard grid, before calling anything "filler".

---

## 4. UDP service — snmp1 (Task 3) — SOLVED

- **Service:** SNMP on **8024/udp** (non-standard port, not 161), SNMP v1/v2c,
  community `public` (as the challenge states: `snmp1.chal.deti:8024/udp`).
- **What it volunteers:** sysDescr `Linux lab-host 6.1.0-18 ... x86_64`, sysContact
  `NetOps <netops@lab.deti>`, sysName `lab-host`, sysLocation `Lab rack 2, shelf B`,
  plus an interface table (`lo`, `eth0`).
- **The twist:** the server answers with a **SET-PDU (0xa3)** instead of a
  GET-RESPONSE (0xa2). Standard Net-SNMP tools abort:
  `snmpwalk: Protocol error (Expected RESPONSE-PDU but got SET-PDU)`.
- **Approach:** read replies directly off the wire with `tcpdump -A udp port 8024`,
  then a small **scapy** walker (`challenges/network/snmp1/snmp-walker.py`) that parses
  the reply regardless of the wrong PDU tag, walking the full tree.
- **Flag location:** private enterprise OID `1.3.6.1.4.1.99999.1.1.0` — outside the
  standard `system` group, so only a full walk finds it.

> **Flag: `flag{3cad557d9709a6a658ae582ce33ab216}`**

---

## 5. DNS (Task 4)

- **Resolver:** challenge containers resolve via podman's internal `10.139.0.1`,
  which forwards to the lab's **dnsmasq 2.91 on 10.110.3.1:53**.
- **Wildcard confirmed:** `*.chal.deti` resolves to `10.110.3.72` for *any* label —
  tested `test.chal.deti`, `6525-27930.chal.deti`, etc., all → `.72`.
- **Enumerated names (all → .72):** `chal.deti`, `ctfd.chal.deti`,
  `leak1..leak10.chal.deti`, `wordpress.chal.deti`, `snmp1.chal.deti`.
- **Impact on host discovery:** because the wildcard answers everything, a name
  resolving tells you **nothing** about whether that service is up. "No response"
  from a name is therefore **not** proof a service is down — you must confirm with a
  port probe. Conversely, every challenge is just a vhost (name + port) on one IP,
  not a separate host.

---

## 6. Stack fingerprint (Task 5)

Two deliberately different build/maintenance profiles on one host:

**A. Python/Flask behind gunicorn — the uniform fleet.**
CTFd (8000) and every info-leak app (8010–8023) return an identical bare
`Server: gunicorn` banner with no version and no OS leak. This uniformity says they
were built from **one template / deployment pipeline** and are maintained together;
hiding the version is the hardened, modern default.

**B. Apache/PHP — the stock vulnerable apps.**
The four Apache apps (8081–8084) are the classic deliberately-insecure training apps —
**bWAPP (8081), DVWA v1.10 (8082), Mutillidae (8083), WordPress (8084)**. They leak OS
**and** version, and the Apache versions are all over the place: `2.4.7 (Ubuntu)` ×2 —
Ubuntu 14.04-era, long EOL — plus `2.4.25 (Debian)` and `2.4.67 (Debian)`. Different
versions across two distros means they were packaged separately at different times,
not templated; DVWA even prints its version straight in the page `<title>`. The
`wordpress` challenge (8084) leans into this explicitly: *"the core beneath has not
seen a patch in many moons."* This is the intended CVE-enumeration surface (Task 2).

**C. Odd ones out.** Node/Express (OWASP Juice Shop, 3000 — also a stock app) and a
bespoke TCP socket service (9001, "True Names") sit outside both stacks.

Security-relevant read: the gunicorn fleet gives an attacker nothing from banners;
the Apache set advertises old, potentially vulnerable software — the intended
"soft" surface.

---

## 7. Surprises / anomalies (reportable per RoE)

1. **Three services ahead of the scoreboard.** 8021 ("Lab recipes"), 8022 ("Bench log"),
   8023 ("Team card") are the **XSS challenges xss1/xss2/xss3** (web) — live on the host
   but not (yet) shown on the scoreboard grid. Exact xssN↔port mapping and release status
   TBD. Not filler: everything running now resolves to a challenge (released or pending)
   or a named stock app.
2. **Port 8084 (wordpress) backend DOWN/flapping.** The :8084 proxy returns a fixed
   90-byte `Failed to daemonise ... No route to host (113)` for every path (5/5 tries)
   — the WordPress container behind it is unreachable. It was briefly up (wpscan saw
   core 7.1.3 via vhost `wordpress.chal.deti`), then dropped. Availability issue to
   report; blocks the `wordpress` challenge until restored.
3. **Non-standard, non-conformant SNMP.** 8024/udp speaks SNMP but replies with a
   SET-PDU, breaking standard clients (documented in §4).
4. **`leak8` not shown on the scoreboard grid** at first view, yet it is live on
   :8017 (robots.txt challenge) — the board just hadn't rendered it; re-confirm.
5. **Exposed Proxmox API** (:3128) on all three infra nodes — expected for a lab, not
   probed, noted for completeness.

---

## 8. Methodology & tooling

`nmap` (host discovery `-sn`; TCP `-sV -T3 -p-`; UDP `-sUV` on 8024), `getent` for
DNS, `curl` for titles/headers/redirects, `tcpdump` + a `scapy` walker for the
non-conformant SNMP service. Timing kept at `-T3` or lower throughout; UDP limited to
small port sets with few retries; content checks run serially. All raw outputs saved
under `10.110.3.72/`; per-challenge scripts live with their writeups in
`challenges/<name>/`, and shared recon helpers under `scripts/`.

---

## 9. Formal CVE / version table (Task 2)

**Caveat:** the `nmap --script vulners` feed (`vulners.txt`) is **lab-seeded and
forward-dated** (it lists `CVE-2026-*` entries), and it matches on version banners only —
it cannot tell a backported-but-patched distro build from a genuinely vulnerable one. So
the rows below are **triage, not proof**. The genuinely actionable items are the EOL
components and the WordPress core RCE; the four stock training apps are vulnerable *by
design at the app layer*, not primarily through server CVEs.

| Software | Version | Port(s) | CVE(s) | CVSS | Exploitability in lab |
|----------|---------|---------|--------|------|-----------------------|
| WordPress core | reports 7.1.3; actually 6.9.x/7.0.x | 8084 | CVE-2026-63030 "wp2shell" (+ CVE-2026-60137 SQLi) | 9.8 | **Unauth RCE.** PoC staged; currently blocked by the backend outage |
| PHP | 5.5.9 (EOL 2016) | 8081, 8083 | CVE-2016-5385 (httpoxy) + many | ~5–8 | Unsupported — no vendor patches; several config-gated |
| Apache httpd | 2.4.7 (Ubuntu 14.04, EOL) | 8081, 8083 | CVE-2014-0226, CVE-2019-0211 | 6.8 / 7.8 | Large surface but mostly local priv-esc / config-gated |
| Apache httpd | 2.4.25 (Debian) | 8082 | CVE-2017-9798 (Optionsbleed), CVE-2017-7679 | 5.3 / 7.5 | Config-dependent — verify module/OPTIONS before claiming |
| Apache httpd | 2.4.67 (Debian, ~2023) | 8084 | few / minor | Low | Low — recent branch, smallest surface |
| OpenSSH | 10.0p2 | 22 (infra) | — | — | Out of scope; 2026-dated feed = triage only |
| Juice Shop / DVWA v1.10 / bWAPP / Mutillidae | — | 3000 / 8082 / 8081 / 8083 | n/a (intentional) | n/a | App-layer by design, not CVE-driven |

**Read:** only two rows are "patch now" — **WordPress (Critical, pre-auth RCE)** and the
**EOL PHP/Apache** stacks (High, because unsupported regardless of CVSS). Everything else
is either config-gated (verify first) or intentionally vulnerable at the app layer.
