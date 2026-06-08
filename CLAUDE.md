# Nessus Claude Analysis Toolkit

Analyzes Nessus CSV exports — parses findings, verifies each one live with bash (curl, openssl, nmap), and produces a confirmed `findings.md`. No exploitation, confirmation only.

---

## Security Rules

- Web findings: read-only (`curl` headers/status only — no payloads, no auth)
- Verify findings, never exploit them
- Unreachable host → mark "Could not verify", never assume confirmed

---

## Known Excluded Findings

Findings acknowledged by the developer/asset owner. Do not verify these — just add a note in `findings.md`:

> **`<Finding Name>`** — Excluded from this assessment as acknowledged by the developer/asset owner.

| Finding | Reason |
|---------|--------|
| <!-- Finding Name --> | <!-- accepted risk / vendor limitation / internal policy --> |

---

## Excluded Findings in findings.md

When excluded findings are present, append at the end:

```markdown
## Excluded Findings

| Finding | Note |
|---------|------|
| <Finding Name> | Excluded from this assessment as acknowledged by the developer/asset owner. |
```
