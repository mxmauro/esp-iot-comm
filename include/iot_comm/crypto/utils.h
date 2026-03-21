#pragma once

#include "sdkconfig.h"
#include <stdint.h>
#include <esp_err.h>

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Fills a buffer with cryptographically secure random bytes.
esp_err_t randomize(uint8_t *dest, size_t destLen);

// Compares two buffers without leaking timing information.
bool constantTimeCompare(const void *buf1, const void *buf2, size_t len);

#ifdef __cplusplus
};
#endif // __cplusplus
