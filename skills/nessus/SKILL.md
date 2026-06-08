---
name: nessus
description: Nessus CSV analysis and finding verification. Use when given a Nessus CSV file or a directory of CSV files to parse, verify findings, and generate a findings.md report. Handles TLS/SSL findings, web findings (read-only), service detection, and informational findings. Always verifies findings with live bash checks before writing to the report.
---

# NESSUS FINDING ANALYSIS SKILL

Given a Nessus CSV file or a directory of CSVs, produce a verified findings report.

---

## SECURITY RULES (non-negotiable)

1. **Web findings = read-only** — only check response headers and HTTP status codes. No payloads, no fuzzing, no authentication attempts, no data modification.
2. **No exploitation** — verification confirms a finding exists, never exploits it.
3. **No destructive commands** — no `rm`, no config changes on target systems.
4. **Report what you observe** — if a check is inconclusive, say so. Do not guess.
5. **Bash for verification** — all live checks use bash (curl, openssl, nmap). Python scripts are for CSV parsing only.

---

## WORKFLOW

### Step 1 — Parse the CSV(s)

```bash
# Quick summary of all findings
python3 scripts/parse_csv.py <scan.csv> --names-only

# Get all hosts affected by a specific finding
python3 scripts/hosts_by_finding.py <scan.csv> "HSTS" --ips-only

# Generate full findings.md automatically
python3 scripts/csv_to_findings_md.py <dir_or_csv> -o findings.md
```

### Step 2 — Verify each finding with bash

Use the verification commands below based on finding type. Always replace `<host>` and `<port>`.

#### HSTS Missing
```bash
curl -sk -o /dev/null -D - --max-time 8 https://<host> | grep -i strict-transport-security
# Empty = CONFIRMED missing
```

#### Discouraged Cipher Suites (DHE-RSA)
```bash
# Check if DHE (non-ECDHE) is accepted
openssl s_client -connect <host>:<port> -tls1_2 -cipher 'DHE:!ECDHE:!aNULL:!eNULL' 2>&1 </dev/null | grep 'New,'
# Full cipher list
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
curl -sk -D - --max-time 8 https://<host>:<port>/ | head -20  # web only, read-only
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

### Step 3 — Write findings.md

For each verified finding include:
- **Status**: CONFIRMED / PARTIALLY CONFIRMED / NOT CONFIRMED
- **What was run**: exact bash command
- **What it returned**: actual output excerpt
- **Affected hosts**: list from CSV
- **Fix**: one-line remediation

---

## OUTPUT FORMAT (per finding)

```markdown
## <Finding Name>
**Status:** CONFIRMED
**Severity:** Medium | **Affected:** N hosts

<one-line description>

**Verified with:**
\`\`\`bash
<exact command run>
\`\`\`
**Result:** <output excerpt>

**Affected hosts:**
- host:port/proto

**Fix:** <short remediation>
```

---

## NOTES FOR SPECIFIC FINDING TYPES

| Finding | Web? | Notes |
|---------|------|-------|
| HSTS Missing | Yes | curl headers only |
| SSL/TLS Cipher Suites | No | openssl + nmap |
| Post-Quantum Ciphers | No | openssl -msg for Peer Temp Key |
| Shor's HNDL | No | same as post-quantum |
| Session Resume | No | openssl sess_out/sess_in |
| TCP Timestamps | No | nmap -O or sysctl |
| UPnP | No | nmap -sU, may be filtered externally |
| Service Detection | Maybe | nmap -sV, curl for web ports |

---

## SELF-UPDATING THIS SKILL

This file is a living document. After completing a Nessus workflow session, update this skill with anything learned that would help future sessions. Do this by editing this file directly.

### When to update

- A new finding type was encountered that has no entry in the verification table above — add a new bash verification block and a row to the notes table.
- A verification command failed or gave misleading output — note the caveat and the corrected approach.
- A new script was added to `scripts/` — document its usage in Step 1.
- A finding category repeatedly produced false-positives or false-negatives — add a warning note under that finding's section.
- A new workflow pattern emerged that saved time (e.g. batch verification loop, grep shortcut) — add it as a tip under the relevant step.

### How to update

1. Add new finding verification blocks under **Step 2** in the same format as existing ones (heading + bash block + expected output).
2. Add a row to the **NOTES FOR SPECIFIC FINDING TYPES** table.
3. If a new script was written, add its invocation under **Step 1**.
4. Keep entries concise — one bash block per finding type, one-line fix, no paragraphs.
5. Do not remove existing entries; mark deprecated commands with `# DEPRECATED:` and the reason.

### Keep it small

**Do not let this file grow large.** Before adding anything, ask: is this non-obvious and reusable across sessions? If not, skip it. After adding, prune: merge similar entries, delete deprecated blocks once confirmed unused, replace verbose explanations with a single line. The goal is a file you can read in under two minutes. If it grows beyond ~200 lines, compact it — preserve the commands and the table, cut the prose.

### Example — adding a new finding

If you encounter "SMB Signing Disabled" and verify it with:
```bash
nmap --script smb2-security-mode -p 445 <host>
# Look for "Message signing enabled but not required"
```
Add it as a new block under Step 2 and a row `| SMB Signing Disabled | No | nmap smb2-security-mode script |` to the table.
