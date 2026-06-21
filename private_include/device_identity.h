#pragma once

#include "iot_comm/iot_comm.h"
#include <esp_err.h>

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t deviceIdentityInit(const IotCommStorageCallbacks_t *storage);
void deviceIdentityDeinit();

esp_err_t deviceIdentityGetPublicKey(uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);
esp_err_t deviceIdentitySignHash(const uint8_t hash[P256_HASH_SIZE], uint8_t signature[P256_SIGNATURE_SIZE]);

#ifdef __cplusplus
}
#endif // __cplusplus
