#pragma once

#include "sdkconfig.h"
#include <esp_err.h>
#include <stdint.h>

#if (!defined(CONFIG_MBEDTLS_HKDF_C))
    #error This library requires CONFIG_MBEDTLS_HKDF_C to be enabled
#endif

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t hkdfSha256DeriveKey(const uint8_t *key, size_t keyLen, const uint8_t *salt, size_t saltLen,
                              const uint8_t *info, size_t infoLen, uint8_t *keyOut, size_t keyOutLen);

#ifdef __cplusplus
}
#endif // __cplusplus
