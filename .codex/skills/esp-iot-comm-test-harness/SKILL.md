---
name: esp-iot-comm-test-harness
description: Extend and maintain the esp-iot-comm Unity test harness. Use when Codex changes logic that can be exercised under test/main, adds coverage for crypto or utility helpers, updates API defaults, or needs to decide whether a library improvement should ship with targeted regression tests.
---

# Esp Iot Comm Test Harness

This skill is for the repository's existing Unity harness under `test/main/`. Use it for targeted regression coverage, not for UI flow tests or broad integration infrastructure redesign.

## Read First

1. Read `AGENTS.md`.
2. Read the production file you are changing.
3. Read `test/main/main.cpp` and the relevant existing `test/main/test_*.cpp` file.
4. If the changed code is mostly protocol, provisioning, OTA, or crypto, also load the matching subsystem skill first and use this skill only for the testing portion.

## Coverage Heuristics

- Add or update tests when behavior changes in:
  - `src/crypto/*.cpp`,
  - `src/utils/*.cpp`,
  - exported default config helpers,
  - parsing and validation helpers,
  - deterministic derivation logic.
- Prefer pure, deterministic tests that do not need live Wi-Fi, HTTP server tasks, or captive portal UI execution.
- When a behavior is not realistically testable in the current harness, say so explicitly and avoid fake coverage that only restates implementation details.

## Repository-Specific Patterns

- `test/main/main.cpp` is only the Unity entry point; keep it that way.
- Test files follow `test/main/test_*.cpp`.
- Existing tests already group around:
  - crypto vectors and round trips,
  - default config contracts,
  - binary reader/writer behavior,
  - IP and hostname parsing.
- Match the local assertion style with `TEST_ASSERT_*` macros and keep helpers file-local.

## Update Workflow

1. Identify the smallest observable contract of the changed code.
2. Reuse an existing test file if the topic matches; create a new `test_*.cpp` only when the topic does not fit cleanly.
3. Prefer one focused regression per behavior over large scenario scaffolding.
4. Assert both success and failure paths for security-sensitive or bounds-sensitive code.
5. If the code change affects only generated web assets or runtime-only ESP flows, do not force a harness change; note the testing gap instead.

## Guardrails

- Do not weaken tests to match a bug unless the requested behavior changed intentionally.
- Do not add randomness without fixed seeds or deterministic fixtures.
- Keep tests independent from execution order.
- Avoid introducing heavyweight mocking or host-only abstractions into component code just to satisfy the current harness.
