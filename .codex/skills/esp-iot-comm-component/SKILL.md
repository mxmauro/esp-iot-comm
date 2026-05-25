---
name: esp-iot-comm-component
description: Work on the esp-iot-comm repository as an ESP-IDF component that combines authenticated WebSocket/UDP command transport, provisioning, captive portal onboarding, OTA helpers, and embedded web assets. Use when Codex needs repository-wide context, must choose the right subsystem skill, or is changing C/C++ component code, public headers, build packaging, tests, or cross-cutting behavior in this project.
---

# Esp Iot Comm Component

This repository is an ESP-IDF component first. Keep changes small, preserve the split between `include/`, `private_include/`, `src/`, and `test/main/`, and prefer security-preserving behavior when a design tradeoff is unclear.

## Start Here

1. Read `AGENTS.md` before editing anything. Treat it as the local operating contract.
2. Read [references/layout.md](references/layout.md) for the subsystem map and the paths that matter.
3. Read [references/validation.md](references/validation.md) before changing build packaging, tests, or embedded web assets.
4. If the task is mostly transport/protocol/session work, switch to `esp-iot-comm-protocol`.
5. If the task is mostly onboarding, captive portal integration, or Wi-Fi state flow, switch to `esp-iot-comm-provisioning`.
6. If the task is mostly Svelte/Vite UI work or embedded asset regeneration, switch to `esp-iot-comm-web-ui`.
7. If the task is mostly firmware update state or boot-partition confirmation, switch to `esp-iot-comm-ota`.
8. If the task is mostly AES/HKDF/P-256/SHA logic, key encoding, or ESP-IDF crypto backend differences, switch to `esp-iot-comm-crypto`.

## Working Rules

- Match local style instead of normalizing files.
- Prefer fail-closed behavior on auth, crypto, protocol, and provisioning paths.
- Keep public API changes in `include/` deliberate and minimal.
- Extend `test/main/test_*.cpp` when behavior changes in protocol, crypto, parsing, OTA, or provisioning logic.
- Do not hand-edit generated captive portal assets under `src/captive_portal/web-dist/`.

## Repository Facts

- Core server/protocol logic lives in `src/iot_comm.cpp`.
- Provisioning and Wi-Fi lifecycle live in `src/provisioning/wifi.cpp`.
- Captive portal HTTP handlers and provisioning decryption live in `src/captive_portal/captive_portal.cpp`.
- Frontend sources live in `src/captive_portal/web-src/`.
- Embedded build outputs live in `src/captive_portal/web-dist/`.
- The component embeds `index.html`, `assets/app.js`, and `assets/app.css` from `web-dist` through `CMakeLists.txt`.

## References

- [references/layout.md](references/layout.md)
- [references/validation.md](references/validation.md)
