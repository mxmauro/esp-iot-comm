#pragma once

#include "sdkconfig.h"
#include <esp_err.h>
#include <stdint.h>

#if (!defined(CONFIG_MBEDTLS_HKDF_C)) || (!defined(CONFIG_MBEDTLS_AES_C)) || (!defined(CONFIG_MBEDTLS_GCM_C))
    #error This library requires CONFIG_MBEDTLS_HKDF_C, CONFIG_MBEDTLS_AES_C and CONFIG_MBEDTLS_GCM_C to be enabled
#endif

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t aesDeriveKey(const uint8_t *key, size_t keyLen, const uint8_t *salt, size_t saltLen, const uint8_t *info, size_t infoLen,
                       uint8_t *keyOut, size_t keyOutLen);

// Size of ciphertextOut must be plaintextLen plus 16 bytes for tag
esp_err_t aesEncrypt(const uint8_t *key, size_t keyLen, const uint8_t *plaintext, size_t plaintextLen,
                     const uint8_t *iv, size_t ivLen, const uint8_t *aad, size_t aadLen,
                     uint8_t *ciphertextOut);
// Size of plaintextOut will be ciphertextLen minus 16 bytes because ciphertext must include the tag at the end
esp_err_t aesDecrypt(const uint8_t *key, size_t keyLen, const uint8_t *ciphertext, size_t ciphertextLen,
                     const uint8_t *iv, size_t ivLen, const uint8_t *aad, size_t aadLen,
                     uint8_t *plaintextOut);

#ifdef __cplusplus
}
#endif // __cplusplus
