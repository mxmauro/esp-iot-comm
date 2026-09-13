---
name: embedded-security-expectations
description: Apply shared security expectations when changing embedded state, storage, transport, crypto, provisioning, or concurrency code.
---

# Embedded Security Expectations

- Fail closed. Return an error on invalid state, malformed input, authentication failure, or initialization failure rather than continuing with partial state.
- Preserve or strengthen null, bounds, length, state, and protocol-invariant validation. Do not weaken checks for convenience.
- Do not log or expose secrets, keys, credentials, tokens, raw device identifiers, or sensitive buffer contents.
- Minimize race windows and partial-state exposure around keys, nonces, counters, persistent records, buffers, mutexes, tasks, and reset paths. Leave objects in a safe, reusable state after failure.
- Avoid dynamic allocation in hot paths or synchronization-sensitive code unless the existing design already requires it.
- Apply specialist repository guidance when changing cryptography, session/authentication state, storage, task lifetime, or provisioning flows.
