# Validation

## Default Checks

- Run the smallest relevant check first.
- Prefer targeted test updates in `test/main/test_*.cpp` when behavior changes.
- If Web UI sources change, rebuild `src/captive_portal/web-dist/` instead of editing embedded files directly.

## Build and Packaging

- `CMakeLists.txt` embeds:
  - `src/captive_portal/web-dist/index.html`
  - `src/captive_portal/web-dist/assets/app.js`
  - `src/captive_portal/web-dist/assets/app.css`
- `idf_component.yml` excludes `src/captive_portal/web-src/**/*`, `examples/**/*`, and `test/**/*` from published component contents.

## Risk Areas

- `src/iot_comm.cpp`: auth, counters, session ownership, UDP/WebSocket transport, OTA command flow.
- `src/captive_portal/captive_portal.cpp`: request validation, encrypted onboarding envelope, root key and hostname setup.
- `src/provisioning/wifi.cpp`: SoftAP/STA transitions, retries, hostname storage, callback ordering.
