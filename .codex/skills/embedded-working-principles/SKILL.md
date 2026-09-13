---
name: embedded-working-principles
description: Apply shared engineering principles when changing ESP-IDF applications or libraries.
---

# Embedded Working Principles

- State material assumptions and surface real ambiguity or tradeoffs instead of silently choosing a different behavior.
- Make the smallest change that solves the requested problem. Do not add speculative abstractions, configurability, or behavior.
- Keep diffs surgical. Preserve unrelated user changes and remove only imports, variables, or helpers made unused by the change.
- Define a proportionate verification target before editing. Prefer focused checks that demonstrate the changed behavior, and broaden validation only when the change scope warrants it.
- Preserve repository boundaries: public headers, internal implementation, tests, generated assets, and packaging metadata each have distinct roles. Do not cross those boundaries without a task requirement.
