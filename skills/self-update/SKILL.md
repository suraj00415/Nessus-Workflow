---
name: self-update
description: Guidelines for keeping skill files up to date after a Nessus workflow session. Apply after completing any analysis session where new findings, commands, or patterns were encountered.
---

# SELF-UPDATE SKILL

After completing a Nessus workflow session, update `skills/nessus/SKILL.md` with anything learned that would help future sessions.

---

## When to Update

- A new finding type was encountered with no verification entry → add a bash block and a table row
- A verification command failed or gave misleading output → note the caveat and corrected approach
- A new script was added to `scripts/` → document its usage under Step 1
- A finding repeatedly produced false positives/negatives → add a warning note
- A new workflow pattern saved time (batch loop, grep shortcut) → add as a tip

## How to Update

1. Add new finding blocks under **Step 2** — same format as existing ones (heading + bash block + expected output)
2. Add a row to the **Finding Types Reference** table
3. If a new script was written, add its invocation under **Step 1**
4. Mark deprecated commands with `# DEPRECATED: <reason>` — do not delete until confirmed unused
5. Keep entries concise — one bash block per finding, one-line fix, no paragraphs

## Keep It Small

Before adding anything, ask: is this non-obvious and reusable across sessions? If not, skip it.
After adding, prune: merge similar entries, cut prose, replace explanations with a single line.
Target: readable in under two minutes. If `SKILL.md` exceeds ~150 lines, compact it.

## Example

New finding "SMB Signing Disabled" verified with:
```bash
nmap --script smb2-security-mode -p 445 <host>
# Look for "Message signing enabled but not required"
```
→ Add bash block under Step 2, add row `| SMB Signing Disabled | No | nmap smb2-security-mode |` to the table.
