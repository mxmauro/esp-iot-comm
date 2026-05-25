# OTA Flow

## Main Files

- `include/iot_comm/ota/ota.h`: exported OTA helper API.
- `src/ota/ota.cpp`: transport-agnostic OTA state machine built on ESP-IDF OTA APIs.
- `src/iot_comm.cpp`: built-in OTA command handlers (`CMD_OTA_BEGIN`, `CMD_OTA_WRITE`, `CMD_OTA_CANCEL`) and reboot scheduling after successful completion.

## Helper Invariants

- Only one OTA update may be active at a time.
- `otaBegin()` must reject a new update when one is already active.
- `otaWrite()` must reject writes that would exceed the declared image size and cancel the in-progress update on fatal write/finalize errors.
- `otaCancel()` must clear all in-memory OTA state.
- `otaVerifyAndConfirmNewFirmware()` only acts when the running image is `ESP_OTA_IMG_PENDING_VERIFY`.

## Repository Integration

- The command channel drives OTA by sending:
  - image size to `otaBegin()`
  - chunk payloads to `otaWrite()`
  - cancellation to `otaCancel()`
- `src/iot_comm.cpp` uses a session flag to track whether OTA is active for that session.
- A successful OTA write completion triggers a delayed reboot task from the command layer, not from `src/ota/ota.cpp`.

## Validation Focus

- Partial write then cancel.
- Oversized write rejection and cleanup.
- Final chunk completion path.
- Boot partition selection after successful write.
- Pending-verify confirmation and rollback path after reboot.
