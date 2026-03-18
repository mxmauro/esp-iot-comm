#pragma once

#include "sdkconfig.h"
#include <cstdint>
#include <esp_err.h>

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t randomize(uint8_t *dest, size_t destLen);

bool constantTimeCompare(const void *buf1, const void *buf2, size_t len);

#ifdef __cplusplus
};
#endif // __cplusplus
