# OTA Update Flow

This module provides the low-level OTA helpers declared in `include/iot_comm/ota/ota.h`. It is intentionally small: it does not define how
firmware chunks are transported, only how an update is written, cancelled, and confirmed.

## How It Is Meant To Be Used

The usual flow is:

1. Call `otaBegin()` once the new image size is known.
2. Feed firmware chunks into `otaWrite()` as they arrive.
3. If the transfer is aborted, call `otaCancel()`.
4. After booting the new image, call `otaVerifyAndConfirmNewFirmware()`.

In this repository, OTA transport is usually driven by the command channel provided by `iot_comm`, but the OTA helpers themselves are
transport-agnostic.

## Main APIs

| API                                | Purpose                                   |
|------------------------------------|-------------------------------------------|
| `otaBegin()`                       | Starts an OTA write session.              |
| `otaWrite()`                       | Writes image data and tracks final chunk. |
| `otaCancel()`                      | Aborts the current OTA session.           |
| `otaVerifyAndConfirmNewFirmware()` | Verifies and confirms the running image.  |

## Practical Notes

* When `otaWrite()` reports completion, it only means the full image payload was received. Final validation can still fail afterward.
* `otaVerifyAndConfirmNewFirmware()` accepts an optional application callback before marking the image as valid.
* If your product needs extra firmware checks, this is the place to run them before confirming the new image.

## See Also

* [IoT communication server](IOT_COMM.md)
