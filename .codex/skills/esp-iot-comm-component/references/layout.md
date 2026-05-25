# Repository Layout

## Main Paths

- `include/iot_comm/`: public C API and exported headers.
- `private_include/`: internal-only headers.
- `src/iot_comm.cpp`: authenticated HTTP/WebSocket server, sessions, built-in commands, UDP transport.
- `src/challenge.cpp`, `src/rate_limit.cpp`, `src/user.cpp`: auth support and persistent user model.
- `src/crypto/`: AES, HKDF, P-256, SHA, and helpers.
- `src/provisioning/wifi.cpp`: Wi-Fi manager and provisioning lifecycle.
- `src/captive_portal/captive_portal.cpp`: captive portal request handling and encrypted onboarding payload processing.
- `src/http/http_helpers.cpp`: HTTP utility helpers shared by server and captive portal code.
- `src/ota/ota.cpp`: transport-agnostic OTA helpers.
- `src/utils/`: binary and network helpers.
- `test/main/`: Unity harness and `test_*.cpp` coverage.

## Component Boundaries

- Keep exported API surface in `include/`.
- Avoid leaking implementation details from `private_include/`.
- Treat `src/captive_portal/web-dist/` as generated and `src/captive_portal/web-src/` as editable.
- Preserve `idf_component.yml` include/exclude packaging behavior unless the task explicitly changes distribution contents.
