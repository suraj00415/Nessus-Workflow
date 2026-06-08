---
name: nessus
description: Nessus CSV analysis and finding verification. Use when given a Nessus CSV file or a directory of CSV files to parse, verify findings, and generate a findings.md report.
---

# NESSUS FINDING ANALYSIS SKILL

---

## Step 1 — Parse the CSV(s)

```bash
python3 scripts/parse_csv.py <scan.csv> --names-only
python3 scripts/hosts_by_finding.py <scan.csv> "HSTS" --ips-only
python3 scripts/csv_to_findings_md.py <dir_or_csv> -o findings.md
```

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

| Finding | Web? | Tool |
|---------|------|------|
| HSTS Missing | Yes | curl |
| SSL/TLS Cipher Suites | No | openssl + nmap |
| Post-Quantum / Shor's HNDL | No | openssl -msg |
| Session Resume | No | openssl sess_out/sess_in |
| TCP Timestamps | No | nmap -O |
| UPnP | No | nmap -sU |
| Service Detection | Maybe | nmap -sV |
