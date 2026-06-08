# Nessus Claude Analysis Toolkit

Analyzes Nessus CSV exports — parses findings, verifies each one live with bash (curl, openssl, nmap), and produces a confirmed `findings.md`. No exploitation, confirmation only.

Also performs a **port and service accessibility check** for every unique host in the scan: each detected port is probed and reported as `open`, `closed`, `filtered`, or `open|filtered`. This summary is included in `findings.md` before the individual finding details.

**Always produces a single `findings.md`** — even when a directory contains multiple CSVs. All scans are merged into one report; per-CSV output files are never created.

---

## Security Rules

These apply globally — in all commands, skills, and sessions. No exceptions.

- **Web findings are read-only** — `curl` headers/status only. No payloads, no login attempts, no form submissions, no data modification.
- **Verify, never exploit** — a confirmed finding is documented, never abused.
- **No target modification** — zero writes, zero config changes on scanned systems.
- **Bash for live checks, Python for CSV parsing** — clean separation, always.
- **Unreachable host** → mark "Could not verify (unreachable)". Never assume confirmed.
- **Inconclusive result** → say so. Do not guess.
- **One findings.md per run** — multiple CSVs in a directory are merged into a single `findings.md`. Never create per-CSV output files.

---

## Port & Service Accessibility Check

After parsing CSVs and before verifying any finding, run a port and service check for every unique host in the scan.

**Goal:** determine whether each port Nessus detected is actually reachable from this machine. Report each port as:

| State | Meaning |
|-------|---------|
| `open` | Port accepted a connection — service is live |
| `closed` | Host replied with RST/ICMP — port reachable but nothing listening |
| `filtered` | No reply or ICMP unreachable — firewall or ACL blocking |
| `open\|filtered` | UDP / ambiguous — nmap cannot distinguish |

**Commands:**
```bash
# TCP — all ports detected by Nessus for a host
nmap -sT -Pn -p <port1,port2,...> --open -T4 <host>

# UDP ports (if any detected)
nmap -sU -Pn -p <port> --open -T4 <host>

# Service version on open ports
nmap -sV -Pn -p <port1,port2,...> -T4 <host>
```

**Output in findings.md:** Add a `## Port & Service Summary` section at the top (after the executive summary, before individual findings) with a table:

```markdown
## Port & Service Summary

| Host | Port | Protocol | State | Service | Version |
|------|------|----------|-------|---------|---------|
| 10.0.0.1 | 443 | tcp | open | https | nginx 1.24 |
| 10.0.0.1 | 8080 | tcp | filtered | — | — |
```

- If a host is completely unreachable (all ports filtered/closed), note it as **Host unreachable from scanner** and skip finding verification for that host.
- Never skip this section — even if only one host is in the scan.

---

## Known Excluded Findings

> **MANDATORY — CHECK THIS BEFORE VERIFYING ANY FINDING.** If a finding name matches anything in the table below, **STOP — do not run any verification command for it**. Do not curl it, do not openssl it, do not nmap it. Just add it to the Excluded Findings section in `findings.md`. This applies in all commands, skills, and sessions. No exceptions.

Findings acknowledged by the developer/asset owner. Do not verify these — just add a note in `findings.md` under **Excluded Findings**:

> **`<Finding Name>`** — Excluded from this assessment as acknowledged by the developer/asset owner.

| Finding | Reason |
|---------|--------|
| HSTS Missing | Acknowledged by developer/asset owner — accepted risk |
| TLS Certificate Issues (expired, self-signed, untrusted CA) | Acknowledged by developer/asset owner — accepted risk |
| TLS Version Vulnerabilities (TLS 1.0, TLS 1.1, SSLv3, POODLE, BEAST, etc.) | Acknowledged by developer/asset owner — accepted risk |
| Weak / Discouraged Cipher Suites (DHE, RC4, 3DES, NULL, EXPORT, etc.) | Acknowledged by developer/asset owner — accepted risk |
| Apache Tomcat Vulnerabilities (all severities — CVEs, misconfigs, outdated versions) | Acknowledged by developer/asset owner — unpatched, accepted risk |
| SSL/TLS Certificate Expiry | Acknowledged by developer/asset owner — accepted risk |
| Post-Quantum / Shor's Algorithm Vulnerabilities (HNDL attack, classical-only key exchange, no MLKEM/Kyber/post-quantum KEM) | Acknowledged by developer/asset owner — accepted risk |

---

## Excluded Findings in findings.md

When excluded findings are present, append at the end of the report:

```markdown
## Excluded Findings

| Finding | Note |
|---------|------|
| <Finding Name> | Excluded from this assessment as acknowledged by the developer/asset owner. |
```
