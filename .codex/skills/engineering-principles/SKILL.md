---
name: engineering-principles
description: Apply focused, correctness-first engineering practices for implementation, diagnosis, review, and testing across codebases.
---

# Engineering Principles

## Working principles

- Read applicable repository guidance first. State material assumptions and tradeoffs; ask for direction when requirements or nearby code are genuinely unclear.
- Make the smallest change that solves the requested behavior. Do not add speculative features, configuration, abstractions, or unrelated cleanup.
- Preserve unrelated user changes and keep the diff limited to the behavior, its tests, and directly required documentation or project metadata.
- Define the verification target before editing. Start with the narrowest meaningful check and broaden it only when shared behavior is affected.
- Respect public/internal boundaries and generated, vendored, dependency, secret, and user-local paths. Change them only when the task explicitly includes them.

## Correctness and security

- Prioritize correctness around synchronization, cancellation, atomics, ownership, lifecycle changes, I/O boundaries, validation, and state management.
- Fail safely on invalid state or misuse; return failure or otherwise follow the repository's established error convention rather than silently proceeding with corrupted state.
- Preserve or strengthen validation and safety invariants. Do not expose partial state during initialization, shutdown, cancellation, or error paths.
- Revalidate functional and security-sensitive changes, especially work involving concurrency, authentication, authorization, cryptography, parsing, serialization, filesystems, or networking.
- Do not log credentials, tokens, keys, or other sensitive internal data. Also use `$secure-code-changes` when security-sensitive behavior is in scope.

## Verification

- Update or extend tests for changed behavior, especially lifecycle, cancellation, error-path, parsing, validation, and boundary cases.
- Run the narrowest useful validation first, then broaden it when shared behavior is affected. Run relevant project-specific validation for the changed area.
- For concurrency-sensitive Go changes, prefer both ordinary and race-enabled tests unless the user explicitly declines.
- Report validation that could not be run and what remains unverified.
