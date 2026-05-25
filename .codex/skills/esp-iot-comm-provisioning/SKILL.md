---
name: esp-iot-comm-provisioning
description: Work on the onboarding and network setup flow in esp-iot-comm. Use when Codex is changing `src/provisioning/wifi.cpp`, `src/captive_portal/captive_portal.cpp`, provisioning-related public headers, SoftAP-to-STA transitions, hostname handling, root-key onboarding, or captive portal request validation and integration.
---

# Esp Iot Comm Provisioning

Use this skill for first-boot setup and network lifecycle work. The main concern is preserving a clean handoff from captive portal input to stored credentials, hostname setup, and authenticated communication bootstrap.

## Workflow

1. Read [references/onboarding-flow.md](references/onboarding-flow.md).
2. Determine whether the change belongs to Wi-Fi manager state, captive portal request handling, or the handoff between them.
3. Keep validation close to input boundaries: SSID, password, hostname, root key, and encrypted payload parsing.
4. Preserve callback ownership and ordering when handing provisioning results back to the application.
5. Call out manual verification if the change affects captive portal behavior or STA/SoftAP transitions.

## Rules

- Keep `wifiMgrSetHostname()` and `iotCommInitRootUserPublicKey()` integration behavior explicit when onboarding data changes.
- Preserve RFC1123 hostname validation and current Wi-Fi credential constraints unless the task explicitly changes them.
- Do not weaken captive portal provisioning payload validation or decryption checks.
- Keep generated UI assets separate from the HTTP handlers that serve them.

## References

- [references/onboarding-flow.md](references/onboarding-flow.md)
