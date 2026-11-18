---
name: code-review
description: Perform a read-only, defect-first review of a specified code change and report actionable findings with evidence.
---

# Code Review

Use this skill for a requested review of uncommitted changes, a commit, a branch diff, or an explicitly supplied change set. Do not modify files, create commits, push branches, post external comments, or expand the target without authorization.

## Review the change

1. Read applicable repository guidance and identify generated, vendored, and user-owned paths.
2. Inspect the complete requested diff and enough surrounding code, tests, and call sites to validate each potential finding.
3. Focus on regressions introduced by the change: correctness, security, performance, or meaningful maintainability defects.
4. Check error paths, lifecycle transitions, input validation, concurrency, public compatibility, and relevant tests according to the changed area.

Report a finding only when it is introduced by the reviewed change, discrete, actionable, demonstrable from the code, and likely worth fixing. Do not report style nits, speculative concerns, intentional behavior changes, or pre-existing defects.

## Write the result

- Present findings first, ordered by severity, with a concise title, affected path and line, concrete scenario, and impact.
- Use `P0` for a universal release blocker, `P1` for urgent defects, `P2` for ordinary defects, and `P3` for low-impact but actionable defects.
- If there are no qualifying findings, say `No findings.`
- End with a brief overall assessment and any material test gaps or residual risks.
