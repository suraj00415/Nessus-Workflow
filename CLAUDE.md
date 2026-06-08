# Nessus Claude Analysis Toolkit

Analyzes Nessus CSV exports — parses findings, verifies each one live with bash (curl, openssl, nmap), and produces a confirmed `findings.md`. No exploitation, confirmation only.

---

## Security Rules

These apply globally — in all commands, skills, and sessions. No exceptions.

- **Web findings are read-only** — `curl` headers/status only. No payloads, no login attempts, no form submissions, no data modification.
- **Verify, never exploit** — a confirmed finding is documented, never abused.
- **No target modification** — zero writes, zero config changes on scanned systems.
- **Bash for live checks, Python for CSV parsing** — clean separation, always.
- **Unreachable host** → mark "Could not verify (unreachable)". Never assume confirmed.
- **Inconclusive result** → say so. Do not guess.

---

## Known Excluded Findings

Findings acknowledged by the developer/asset owner. Do not verify these — just add a note in `findings.md` under **Excluded Findings**:

> **`<Finding Name>`** — Excluded from this assessment as acknowledged by the developer/asset owner.

| Finding | Reason |
|---------|--------|
| <!-- Finding Name --> | <!-- accepted risk / vendor limitation / internal policy --> |

---

## Excluded Findings in findings.md

When excluded findings are present, append at the end of the report:

```markdown
## Excluded Findings

| Finding | Note |
|---------|------|
| <Finding Name> | Excluded from this assessment as acknowledged by the developer/asset owner. |
```
