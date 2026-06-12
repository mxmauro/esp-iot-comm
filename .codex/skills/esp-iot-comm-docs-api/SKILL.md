---
name: esp-iot-comm-docs-api
description: Keep the esp-iot-comm public API, integration docs, and examples aligned. Use when Codex changes exported headers under include/, updates README.md or docs/*.md, adds or removes onboarding or transport behavior that affects user-facing guidance, or needs to review whether a library improvement also requires documentation changes.
---

# Esp Iot Comm Docs Api

This skill covers the public library contract rather than one implementation subsystem. Use it when the risk is "the code changed, but the user-facing story did not."

## Read First

1. Read `AGENTS.md`.
2. Read the changed exported headers under `include/iot_comm/`.
3. Read the matching docs page in `docs/` and the affected section in `README.md`.
4. If onboarding behavior changes, also read `docs/WIFI_PROVISIONING.md` and `docs/CAPTIVE_PORTAL.md`.
5. If command transport or OTA behavior changes, also read `docs/IOT_COMM.md` and `docs/OTA.md`.

## Update Workflow

1. Identify the user-visible contract that changed:
   - initialization flow,
   - callback timing,
   - stored data,
   - security requirements,
   - packaging or support matrix,
   - onboarding fields,
   - transport semantics.
2. Update the narrowest docs surface that explains that contract.
3. Update `README.md` only when the change affects first-contact understanding, feature claims, requirements, or installation.
4. Keep docs concrete. Prefer "call X before Y" over vague descriptions.
5. Preserve the distinction between:
   - public API in `include/`,
   - application integration guidance in `docs/`,
   - generated or internal implementation details that should stay out of public docs.

## Repository-Specific Checks

- `docs/IOT_COMM.md` explains ownership of sessions, replies, and root-key initialization.
- `docs/WIFI_PROVISIONING.md` explains provisioning state transitions and hostname rules.
- `docs/CAPTIVE_PORTAL.md` explains the onboarding payload fields and application handoff.
- `docs/OTA.md` explains transport-agnostic OTA sequencing.
- `README.md` should stay high level and not become a second full manual.

## Guardrails

- Do not document internal-only helpers from `private_include/` unless they become public API.
- Do not claim Linux simulator support; `CMakeLists.txt` exits early for `linux`.
- Keep security wording fail-closed. If an operation can fail due to invalid credentials, malformed input, or storage errors, say so plainly.
- When a behavior change is not documented because it is intentionally internal, state that decision in the task response.
