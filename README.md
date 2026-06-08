# Nessus Claude Analysis Toolkit

A workflow for analyzing Nessus scan CSV exports with Claude Code.
Drop CSV files in a session folder, run `/nessus` or `/run`, get a verified `findings.md`.

---

## Structure

```
session-dir/
├── .claude/
│   └── commands/
│       ├── nessus.md     # /nessus slash command
│       └── run.md        # /run slash command
├── scripts/
│   ├── parse_csv.py            # Summary of all findings from a CSV
│   ├── hosts_by_finding.py     # Extract hosts for a specific finding
│   └── csv_to_findings_md.py  # Generate full findings.md from CSV(s)
├── skills/
│   └── nessus/
│       └── SKILL.md            # Skill loaded by Claude for nessus analysis
├── <scan>.csv                  # Nessus CSV export(s)
└── findings.md                 # Output report (generated)
```

---

## Usage

### Option 1 — Slash commands (open Claude Code in this directory)

```
/nessus scan.csv
/run .
```

### Option 2 — Run scripts directly

```bash
# Quick summary of all findings
python3 scripts/parse_csv.py scan.csv --names-only

# Full grouped detail
python3 scripts/parse_csv.py scan.csv

# Filter by finding name
python3 scripts/parse_csv.py scan.csv --filter-name "SSL"

# Get all IPs affected by a specific finding (pipe to bash verification)
python3 scripts/hosts_by_finding.py scan.csv "HSTS" --ips-only

# Generate findings.md from all CSVs in a directory
python3 scripts/csv_to_findings_md.py . -o findings.md
```

---

## Workflow

1. Export scan from Nessus as **CSV** and place in a session directory
2. Open Claude Code in that directory
3. Run `/run .` — Claude will:
   - Parse all CSVs with the Python scripts
   - Verify each finding live using bash (curl, openssl, nmap)
   - Write `findings.md` with confirmed/unconfirmed status and exact commands used

---

## Security Rules

- **Web findings**: read-only only — `curl` headers/status check. No payloads, no authentication, no data modification.
- **Verification only**: findings are confirmed or denied, never exploited.
- **Bash for live checks, Python for CSV parsing** — clean separation.
- If a host is unreachable from the test vantage point, it is marked "Could not verify" not confirmed.

---

## Verification Commands Quick Reference

| Finding | Bash Command |
|---------|-------------|
| HSTS Missing | `curl -sk -D - https://<host> \| grep -i strict-transport` |
| Weak Cipher (DHE) | `openssl s_client -connect <h>:<p> -tls1_2 -cipher 'DHE:!ECDHE:!aNULL:!eNULL' 2>&1 </dev/null \| grep 'New,'` |
| TLS Versions | `for v in tls1 tls1_1 tls1_2 tls1_3; do openssl s_client -connect <h>:<p> -$v 2>&1 </dev/null \| grep '^New,'; done` |
| Post-Quantum | `openssl s_client -connect <h>:<p> -msg 2>&1 </dev/null \| grep 'Peer Temp Key'` |
| Session Resume | `openssl s_client -connect <h>:<p> -sess_out /tmp/s.pem 2>&1 </dev/null && openssl s_client -connect <h>:<p> -sess_in /tmp/s.pem 2>&1 </dev/null \| grep 'Reused,'` |
| Service Banner | `nmap -sV -p <port> <host>` |
| Cipher Enum | `nmap --script ssl-enum-ciphers -p <port> <host>` |
| UPnP | `nmap -sU -p 1900 --script upnp-info <host>` |
| TCP Timestamps | `nmap -O --osscan-limit <host>` |
