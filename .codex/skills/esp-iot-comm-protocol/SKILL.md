---
name: esp-iot-comm-protocol
description: Work on the authenticated command and transport paths in esp-iot-comm. Use when Codex is changing `src/iot_comm.cpp`, `include/iot_comm/iot_comm.h`, session state, command dispatch, WebSocket framing, UDP open/data handling, auth counters, rate limiting, user-management commands, or other protocol and concurrency-sensitive logic.
---

# Esp Iot Comm Protocol

Use this skill for changes where transport rules, session ownership, counters, or reply timing matter. This code is security-sensitive and heavily stateful.

## Workflow

1. Read `include/iot_comm/iot_comm.h` and the relevant block in `src/iot_comm.cpp`.
2. Read [references/command-paths.md](references/command-paths.md).
3. Identify which state is per-server, per-session, or per-packet before editing.
4. Preserve synchronous reply semantics for event callbacks.
5. Prefer narrow changes that maintain current invariants and cleanup patterns.
6. Add or update `test/main/test_*.cpp` when command behavior or parsing rules change.

## Rules

- Treat transport parsing, counters, and key material as fail-closed paths.
- Preserve zeroization and reset behavior on failure.
- Respect locking boundaries: `dispatchMtx` serializes per-session command dispatch; `serverCtx->sessions.mtx` protects membership and shared session visibility.
- Keep public protocol comments in `include/iot_comm/iot_comm.h` aligned with implementation when command layouts change.
- Do not defer `iotCommEventReply*()` or `iotCommSessionClose()` outside the callback that received the event.

## References

- [references/command-paths.md](references/command-paths.md)
