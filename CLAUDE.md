# Nessus Claude Analysis Toolkit

A Claude Code workflow for analyzing Nessus scan CSV exports. Drop CSV files in a session folder, run `/nessus` or `/run`, and get a verified `findings.md` with live-confirmed statuses using bash (curl, openssl, nmap). Python scripts handle CSV parsing; bash handles live verification. No exploitation — confirmation only.

---

## Project Structure

```
nessus-workflow/
├── scripts/
│   ├── parse_csv.py            # Summary of all findings from a CSV
│   ├── hosts_by_finding.py     # Extract hosts for a specific finding
│   └── csv_to_findings_md.py  # Generate full findings.md from CSV(s)
├── skills/nessus/SKILL.md      # Loaded by Claude during /nessus runs
├── CLAUDE.md                   # This file
└── README.md
```

---

## Security Rules

- **Web findings**: read-only — `curl` headers/status only. No payloads, no auth attempts, no data modification.
- **Verification only**: confirm or deny a finding. Never exploit.
- **Bash for live checks, Python for CSV parsing** — no exceptions.
- If a host is unreachable, mark it "Could not verify" — never assume confirmed.

---

## Researcher Section — Known Excluded Findings

The following findings are **acknowledged by the developer / asset owner** and **excluded from the report**. When Claude encounters any of these during a scan session, it must **not** attempt to verify or investigate them. Instead, add a single note in `findings.md` under an **Excluded Findings** heading:

> **Note:** This finding (`<finding name>`) is excluded from the scope of this assessment as acknowledged by the developer/asset owner.

### Excluded Findings List

<!-- Add excluded findings below, one per line, in the format:
- `Finding Name` — reason / reference (e.g., accepted risk, vendor limitation, internal policy)
-->

<!-- PLACEHOLDER: no excluded findings defined yet -->

---

## Output Format (per finding in findings.md)

```markdown
## <Finding Name>
**Status:** CONFIRMED | PARTIALLY CONFIRMED | NOT CONFIRMED | Could not verify
**Severity:** Critical | High | Medium | Low | Info  |  **Affected:** N hosts

<one-line description>

**Verified with:**
```bash
<exact command run>
```
**Result:** <output excerpt>

**Affected hosts:**
- host:port

**Fix:** <short remediation>
```

---

## Excluded Findings Section (in findings.md)

When one or more excluded findings are encountered, append this section at the end of `findings.md`:

```markdown
---

## Excluded Findings

The following findings were identified in the scan data but are excluded from this assessment as acknowledged by the developer/asset owner.

- **<Finding Name>** — This finding is excluded from the scope of this assessment as acknowledged by the developer/asset owner.
```
