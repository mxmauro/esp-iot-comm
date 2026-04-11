#pragma once

#include <esp_err.h>
#include <stddef.h>
#include <stdint.h>

// -----------------------------------------------------------------------------

typedef bool (*OtaFirmwareCheckCallback_t)(void *ctx);

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Starts an OTA update for an image with the provided total size.
esp_err_t otaBegin(uint32_t imageSize);
// Writes firmware data and sets *completed when the last expected chunk was received, even if finalization later fails.
esp_err_t otaWrite(const uint8_t *data, size_t len, bool *completed);

// Cancels the current OTA update and discards any in-progress state.
void otaCancel();

// Verifies the running firmware and confirms it as valid for future boots.
esp_err_t otaVerifyAndConfirmNewFirmware(OtaFirmwareCheckCallback_t cb, void *ctx, bool *mustReboot);

#ifdef __cplusplus
}
#endif // __cplusplus
