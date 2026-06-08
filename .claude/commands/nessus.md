---
description: Analyze Nessus CSV scan results — parse findings, verify them live with bash, and generate a findings.md report. Usage: /nessus <path-to-csv-or-dir>
---

# /nessus

Analyze a Nessus CSV scan and produce a verified findings report.

## References

- Security rules and excluded findings → `CLAUDE.md`
- Verification commands and output format → `skills/nessus/SKILL.md`

## Steps

1. `python3 scripts/parse_csv.py <file> --names-only` — summarize all findings
2. Group and prioritize: Critical → High → Medium → Low → Info
3. Check `CLAUDE.md` for any excluded findings before verifying
4. Verify each security-relevant finding live with bash (see `skills/nessus/SKILL.md`)
5. Write results to `findings.md`

## Usage

```
/nessus scan.csv
/nessus /path/to/scans/
```
