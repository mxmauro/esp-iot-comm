# esp-iot-comm Agent Notes

## Scope and skill routing

These instructions apply to the whole repository. Preserve the component split between public headers in `include/`, internal headers in `private_include/`, implementation in `src/`, and tests in `test/main/`.

- Use the canonical engineering, security, review, repository-text, embedded C/C++, JavaScript/TypeScript, and Svelte component skills as applicable.
- Use canonical `esp-idf-guidance` and local esp-iot-comm domain skills for component, crypto, protocol, OTA, provisioning, web UI, packaging, documentation, and test-harness changes.

## Component constraints

- Keep public headers focused on exported APIs; do not expose implementation from `private_include/` without an intentional API change.
- Editable captive-portal sources are under `src/captive_portal/web-src/`; `web-dist/` is generated embedded output and must be regenerated rather than hand-edited.
- Keep the existing test harness structure: `test/main/main.cpp` and `test/main/test_*.cpp`. Extend tests for changed crypto, utility, protocol, provisioning, or security-sensitive behavior.
- Captive-portal UI behavior lacks automated coverage; identify required manual verification when it changes.
- Preserve Linux-simulator exclusions, component registration, embedded web assets, dependency declarations, and `idf_component.yml` exclusion rules unless the task explicitly changes them.
