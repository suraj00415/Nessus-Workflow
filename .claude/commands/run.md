---
description: Run the full Nessus analysis pipeline on a CSV directory — parses all CSVs, verifies findings, outputs findings.md. Usage: /run <dir>
---

# /run

Full automated pipeline: parse all CSVs in a directory → verify findings → write `findings.md`.

## Usage

```
/run /path/to/nessus/session/dir/
/run .
```

## References

- Security rules and excluded findings → `CLAUDE.md`
- Verification commands and output format → `skills/nessus/SKILL.md`

## Pipeline Steps

1. **Discover** — find all `.csv` files in the given directory
2. **Parse** — `python3 scripts/parse_csv.py <file> --names-only` for each file
3. **Deduplicate** — group same findings across multiple CSVs
4. **Verify** — **MANDATORY FIRST STEP:** cross-check every finding name against the exclusion table in `CLAUDE.md`. Any match → skip all verification, add to Excluded Findings section only. Only after filtering exclusions, run bash checks for remaining findings (see `skills/nessus/SKILL.md`)
5. **Generate** — write `findings.md` with status, command used, output excerpt, affected hosts, and remediation
