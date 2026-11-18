---
name: secure-code-changes
description: Apply cross-language security and reliability practices when changing untrusted input, secrets, state, concurrency, storage, or networked behavior.
---

# Secure Code Changes

Use this skill with local security and platform guidance. Local protocol, cryptographic, storage, and framework rules remain authoritative.

## Preserve security invariants

- Treat external input, persisted data, configuration, IPC, network messages, and decoded payloads as untrusted. Reject malformed, unsupported, truncated, oversized, inconsistent, or trailing data; do not guess missing values.
- Fail closed on invalid state, validation failure, authentication failure, decryption failure, initialization failure, or protocol-invariant failure. Follow the repository's established error and teardown convention.
- Preserve or strengthen null, range, length, type, ownership, authorization, and state validation. Check limits before allocating, iterating, indexing, or performing expensive work.
- Use established, reviewed cryptographic and protocol primitives. Do not substitute custom cryptography, weaken verification, silently downgrade protection, or change encodings/counter/nonce semantics without a deliberate compatible design.

## Secrets, state, and concurrency

- Do not log, expose in errors, persist unnecessarily, or include in URLs/debug output: credentials, keys, tokens, session material, raw sensitive identifiers, signatures, or full sensitive payloads.
- Keep secret-bearing and security-critical state scoped to the minimum lifetime. Clear or invalidate sessions and pending operations according to the repository's established lifecycle after failure or disconnect.
- Avoid partial-state exposure and race windows around initialization, teardown, keys, nonces, counters, persistent records, buffers, locks, tasks, and callbacks.
- Do not hold locks or critical sections across blocking I/O, allocation, delays, untrusted callbacks, or other potentially re-entrant operations. Make ownership and shutdown ordering explicit.

## Verify proportionately

- Add or update focused tests for malformed input, boundary sizes, invalid state transitions, authentication/authorization failures, teardown, and concurrency-sensitive paths that changed.
- Recheck compatibility across supported runtimes or platforms when shared protocol, crypto, serialization, or transport behavior changes.
- Report manual verification needs and residual risk when a relevant environment, device, or integration test cannot run.
