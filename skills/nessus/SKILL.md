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

> **MANDATORY — PROBE ALL PORTS.** You must probe **every port Nessus detected** for every unique host — not just 80/443. This includes non-standard ports such as 8080, 8443, 9200, 22, 3389, 5432, 10933, 1433, or any other port that appears in the CSV. Do NOT limit the port list to common web ports. If Nessus saw it, you probe it. A finding on port 10933 with that port not in the port summary is a reporting failure.

For every unique host in the CSV, collect all ports Nessus detected and probe them:

```bash
# Get ALL unique host:port pairs from CSV — this is your probe list, do not filter it
python3 scripts/parse_csv.py <scan.csv> --hosts-ports

# TCP reachability check — include EVERY port from the CSV for that host
nmap -sT -Pn -p <ALL_ports_from_csv> -T4 <host>
# Example: nmap -sT -Pn -p 22,80,443,3389,5432,8080,9200,10933 -T4 bitbuckettest.example.com

# Service version on open/filtered ports
nmap -sV -Pn -p <ALL_ports_from_csv> -T4 <host>

# UDP (only if Nessus detected UDP ports)
nmap -sU -Pn -p <udp_port> --open -T4 <host>
```

> **Never use `--open`** when building the Port & Service Summary table — `--open` hides `filtered` and `closed` ports, which must still be reported. Use `--open` only for initial quick reachability checks, then always follow with a full port-state scan (without `--open`) for the summary table.

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

> **Finding Types Reference — read this before verifying anything.**
> The commands below are a **reference list only** — not an exhaustive checklist. You are expected to:
> 1. Verify **every finding present in the CSV**, not just the ones listed here.
> 2. Use **any appropriate tool or command** — the commands shown are suggestions, not requirements. If a different curl flag, nmap script, testssl.sh, nikto, or any other tool is better suited, use it.
> 3. Investigate findings that fall outside this table using your best judgement and the appropriate bash tooling.

> **ENUMERATE WHAT YOU FIND.** Confirming a finding is not the end — it is the beginning. If a finding reveals something (a file, a directory, an open service, a version string, exposed data), enumerate it fully and include the results in `findings.md`. Examples:
> - `.DS_Store` confirmed → parse the binary, extract filenames, recurse into each disclosed subdirectory and check for nested `.DS_Store` files, enumerate actual files in each directory using paths from the page source. Report the complete file inventory in the finding.
> - Elasticsearch open → query `/_cat/indices` and `/_cluster/health` (read-only) to show what indices are exposed.
> - Directory listing enabled → list the directory contents and note any sensitive filenames.
> - nginx/Apache version confirmed → cross-reference the exact version against all known CVEs for that version, not just the one Nessus flagged.
> - Open non-standard port → banner-grab it, identify the service, check if it exposes anything sensitive.
>
> **Do not stop at "confirmed". Show what it means.** The goal is for the reader to understand the real-world impact, not just that a vulnerability exists.
>
> | Finding | Web? | Tool |
> |---------|------|------|
> | Port & Service Accessibility | No | nmap -sT / -sU / -sV |
> | HSTS Missing | Yes | curl |
> | SSL/TLS Cipher Suites | No | openssl + nmap |
> | Post-Quantum / Shor's HNDL | No | openssl -msg |
> | Session Resume | No | openssl sess_out/sess_in |
> | TCP Timestamps | No | nmap -O |
> | UPnP | No | nmap -sU |
> | Service Detection | Maybe | nmap -sV |

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

#### Apache Tomcat CVE Verification — PoC Research Required

Apache Tomcat findings are **no longer auto-excluded**. For every Apache Tomcat CVE finding:

1. **Confirm the installed version** from the Plugin Output (Nessus reports `Installed version` — use that, do not probe for version banners).
2. **Look up the specific CVE** for that finding and find a working PoC or deterministic check. Do not assume exploitability — find evidence.
3. **Run the minimum safe check** that confirms vulnerable behaviour without exploiting it. Examples by CVE type:

| CVE type | Safe check |
|----------|-----------|
| Path traversal / info disclosure | `curl -sk --path-as-is "http://<host>:<port>/<payload>"` — check response code and body for path leak |
| Default files exposed (docs, examples) | `curl -sk -o /dev/null -w "%{http_code}" http://<host>:<port>/docs/` — 200 = CONFIRMED |
| Request smuggling / DoS (no safe check possible) | Mark as **Could not safely verify** — note installed version and fixed version from plugin output |
| Version-only CVE (no exploitable endpoint) | Confirm version string via `curl -sk http://<host>:<port>/ -I | grep -i server` or from Nessus plugin output — mark **CONFIRMED (version only)** |

4. **For each Tomcat host**, check whether the management interface is exposed:
```bash
# Manager app — should return 401 if present, 404 if removed
curl -sk -o /dev/null -w "%{http_code}" http://<host>:<port>/manager/html
curl -sk -o /dev/null -w "%{http_code}" http://<host>:<port>/host-manager/html
# 401 = manager present (credential brute-force risk), 404 = removed (good)
```

5. **Check for default example pages** (common misconfiguration):
```bash
for path in /docs/ /examples/servlets/index.html /examples/jsp/index.html /examples/websocket/index.xhtml; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "http://<host>:<port>$path")
  echo "$code  $path"
done
# 200 = CONFIRMED exposed
```

> **Research note:** Before running any check, search for the specific CVE number to understand what the vulnerable condition actually is. A version match alone is sufficient to report as CONFIRMED for CVEs with no safe in-band probe — but always document what you found (or didn't find) and why.

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

