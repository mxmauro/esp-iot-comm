---
name: esp-iot-comm-ota
description: Work on firmware update and rollback-confirmation behavior in esp-iot-comm. Use when Codex is changing `src/ota/ota.cpp`, `include/iot_comm/ota/ota.h`, the OTA built-in command path in `src/iot_comm.cpp`, image-size/write-state handling, cancellation logic, or post-boot firmware validation and reboot decisions.
---

# Esp Iot Comm OTA

Use this skill for OTA helpers and their integration with the command channel. The OTA module is transport-agnostic, but the repository also drives it through built-in commands in `src/iot_comm.cpp`.

## Workflow

1. Read [references/ota-flow.md](references/ota-flow.md).
2. Decide whether the change is in the transport-agnostic helper (`src/ota/ota.cpp`) or in the command transport that invokes it.
3. Preserve the single-active-update invariant unless the task explicitly changes it.
4. Keep failure paths resetting OTA state cleanly.
5. Call out manual verification for real firmware-update behavior if the change affects end-to-end OTA flow.

## Rules

- Keep `otaBegin()`, `otaWrite()`, `otaCancel()`, and `otaVerifyAndConfirmNewFirmware()` semantics aligned with their header comments.
- Treat writes past the expected image size as fatal and preserve the current fail-closed cleanup behavior.
- Keep rollback and reboot signaling explicit when the running image is pending verification.
- Avoid mixing UI or provisioning concerns into this skill; only cross the boundary when the OTA transport path itself changes.

## References

- [references/ota-flow.md](references/ota-flow.md)
