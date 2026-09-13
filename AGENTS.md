# esp-iot-comm Agent Notes

## Scope
- These instructions apply to the whole repository.
- Treat this as an ESP-IDF component first. Preserve the current split between public headers in `include/`, internal headers in `private_include/`, implementation in `src/`, and test code in `test/main/`.
- Do not touch unrelated user changes. This repository may be dirty.

## Shared skills
- Use `embedded-working-principles` for change scope and verification, `embedded-security-expectations` for security-sensitive work, and `esp-idf-guidance` for ESP-IDF and FreeRTOS work.
- Use `embedded-cpp-style` for C/C++ source and headers, `esp-web-style` for captive-portal frontend source, and `repository-file-style` for CMake, YAML, shell, Markdown, and other text files.

## Naming and API conventions
- Preserve established names instead of renaming identifiers for taste:
- Public API types and callbacks use the established `IotComm*` prefixes.
- Internal helpers use the current mixed C/C++ patterns such as `*_t`, `*_s`, and PascalCase wrapper types from dependencies like `Mutex`.

## Captive portal web UI
- The web UI sources live under `src/captive_portal/web-src/`.
- Source files are the editable ones under `src/captive_portal/web-src/`; the files under `src/captive_portal/web-dist/` are build artifacts embedded by the component.
- If a task changes the captive portal UI behavior or assets, update the source files and regenerate the embedded `dist/` outputs instead of hand-editing the built files.
- Keep frontend changes focused on the requested behavior.

## Headers, implementation, and tests
- Keep public headers in `include/` focused on the exported API. Do not leak internal implementation details from `private_include/` unless the task requires an API change.
- Match the surrounding naming style instead of renaming identifiers for taste.
- Extend or update tests in `test/main/` when behavior changes, especially for crypto helpers, binary/network utilities, protocol handling, provisioning, or security-sensitive logic.
- Keep the test harness structure intact: `test/main/main.cpp` plus `test/main/test_*.cpp`.
- The captive portal UI flow is not covered by the current automated tests, so call out any manual verification needed when frontend behavior changes.

## Build files and docs
- Keep Linux-simulator exclusions, component registration structure, embedded web assets, dependency declarations, and `idf_component.yml` exclusions intact unless the task explicitly changes them.

## Editing rules for agents
- If a task creates tension between style and security, prioritize security while keeping the diff as small as possible.
