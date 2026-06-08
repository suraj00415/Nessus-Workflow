---
name: nessus
description: Nessus CSV analysis and finding verification. Use when given a Nessus CSV file or a directory of CSV files to parse, verify findings, and generate a findings.md report.
---

# NESSUS FINDING ANALYSIS SKILL

---

## Step 1 — Parse the CSV(s)

> **SINGLE OUTPUT FILE RULE:** Whether the input is one CSV or a directory of many CSVs, always produce exactly **one** `findings.md`. Never create per-CSV output files (e.g. `scan1_findings.md`, `scan2_findings.md`). Merge all CSVs into a single report.

```bash
# Single CSV
python3 scripts/parse_csv.py <scan.csv> --names-only

# Directory — all CSVs merged, one findings.md output
python3 scripts/csv_to_findings_md.py <dir_or_csv> -o findings.md

# Get hosts/ports across all CSVs in a dir
python3 scripts/hosts_by_finding.py <dir_or_csv> "HSTS" --ips-only
```

If multiple CSVs are present in the directory:
- Parse all of them together — deduplicate findings by name across files
- Merge affected hosts lists so each finding section shows all hosts from all scans
- The Port & Service Summary covers all unique hosts across all CSVs

---

## Step 1.5 — Port & Service Accessibility Check (do this before any finding verification)

For every unique host in the CSV, collect all ports Nessus detected and probe them:

```bash
# Get unique host:port pairs from CSV
python3 scripts/parse_csv.py <scan.csv> --hosts-ports

# TCP reachability check
nmap -sT -Pn -p <port1,port2,...> --open -T4 <host>

# Service version on open ports
nmap -sV -Pn -p <port1,port2,...> -T4 <host>

# UDP (only if Nessus detected UDP ports)
nmap -sU -Pn -p <udp_port> --open -T4 <host>
```

Port state key:

| State | Meaning |
|-------|---------|
| `open` | Service is live and accepting connections |
| `closed` | Host reachable, nothing listening |
| `filtered` | Firewall/ACL blocking — no response |
| `open\|filtered` | UDP ambiguity — cannot distinguish |

Write results into `findings.md` as a `## Port & Service Summary` table **before** all individual findings:

```markdown
## Port & Service Summary

| Host | Port | Protocol | State | Service | Version |
|------|------|----------|-------|---------|---------|
| 10.0.0.1 | 443 | tcp | open | https | nginx 1.24 |
| 10.0.0.1 | 8080 | tcp | filtered | — | — |
```

If a host is entirely unreachable (all ports filtered/no ICMP), mark it **Host unreachable from scanner** and skip all finding verification for that host.

---

## Step 1.6 — MANDATORY EXCLUSION CHECK (do this before any verification)

> **STOP.** Before running any bash command against any finding, check every finding name against the exclusion table in `CLAUDE.md`. If it matches — do not run curl, openssl, or nmap for it. Add it to Excluded Findings in `findings.md` only. No exceptions.
> Also skip verification for any host marked **unreachable** in the Port & Service Summary.

---

## Step 2 — Verify each finding

#### HSTS Missing
```bash
curl -sk -o /dev/null -D - --max-time 8 https://<host> | grep -i strict-transport-security
# Empty = CONFIRMED missing
```

#### Discouraged Cipher Suites (DHE-RSA)
```bash
openssl s_client -connect <host>:<port> -tls1_2 -cipher 'DHE:!ECDHE:!aNULL:!eNULL' 2>&1 </dev/null | grep 'New,'
nmap --script ssl-enum-ciphers -p <port> <host>
```

#### TLS Versions Supported
```bash
for v in tls1 tls1_1 tls1_2 tls1_3; do
  result=$(openssl s_client -connect <host>:<port> -$v 2>&1 </dev/null | grep '^New,')
  echo "$v: ${result:-rejected}"
done
```

#### Post-Quantum / Shor's HNDL
```bash
openssl s_client -connect <host>:<port> -msg 2>&1 </dev/null | grep 'Peer Temp Key'
# 'prime256v1' or 'X25519' without MLKEM/Kyber = CONFIRMED classical-only
```

#### SSL Session Resume
```bash
openssl s_client -connect <host>:<port> -sess_out /tmp/sess.pem 2>&1 </dev/null | grep 'Session-ID:'
openssl s_client -connect <host>:<port> -sess_in /tmp/sess.pem 2>&1 </dev/null | grep 'Reused,'
# 'Reused,' = CONFIRMED
```

#### Service Detection / Banner
```bash
nmap -sV -p <port> <host>
curl -sk -D - --max-time 8 https://<host>:<port>/ | head -20
```

#### TCP/IP Timestamps
```bash
nmap -O --osscan-limit <host>
```

#### UPnP
```bash
nmap -sU -p 1900 --script upnp-info <host>
```

---

## Step 3 — Write findings.md

For each finding include: Status, exact command run, output excerpt, affected hosts, one-line fix.

```markdown
## <Finding Name>
**Status:** CONFIRMED | PARTIALLY CONFIRMED | NOT CONFIRMED | Could not verify
**Severity:** Critical | High | Medium | Low | Info  |  **Affected:** N hosts

<one-line description>

**Verified with:**
\`\`\`bash
<exact command>
\`\`\`
**Result:** <output excerpt>

**Affected hosts:**
- host:port

**Fix:** <short remediation>
```

---

## Finding Types Reference

> **NOTE:** The table and verification commands below are a **reference list only** — not an exhaustive checklist. You are expected to:
> 1. Verify **every finding present in the CSV**, not just the ones listed here.
> 2. Use **any appropriate tool or command** for verification — the commands shown are suggestions, not requirements. If a different curl flag, nmap script, testssl.sh, nikto, or any other tool is better suited, use it.
> 3. Investigate findings that fall outside this table using your best judgement and the appropriate bash tooling.

| Finding | Web? | Tool |
|---------|------|------|
| Port & Service Accessibility | No | nmap -sT / -sU / -sV |
| HSTS Missing | Yes | curl |
| SSL/TLS Cipher Suites | No | openssl + nmap |
| Post-Quantum / Shor's HNDL | No | openssl -msg |
| Session Resume | No | openssl sess_out/sess_in |
| TCP Timestamps | No | nmap -O |
| UPnP | No | nmap -sU |
| Service Detection | Maybe | nmap -sV |
