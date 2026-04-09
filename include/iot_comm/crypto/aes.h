#pragma once

#include "sdkconfig.h"
#include <esp_idf_version.h>
#include <esp_err.h>
#include <stdbool.h>
#include <stdint.h>

#if ESP_IDF_VERSION_MAJOR >= 6
    #include <psa/crypto.h>
#else
    #include <mbedtls/gcm.h>
#endif

#if (!defined(CONFIG_MBEDTLS_AES_C)) || (!defined(CONFIG_MBEDTLS_GCM_C))
    #error This library requires CONFIG_MBEDTLS_AES_C and CONFIG_MBEDTLS_GCM_C to be enabled
#endif

// -----------------------------------------------------------------------------

typedef struct AesContext_s {
#if ESP_IDF_VERSION_MAJOR >= 6
    psa_key_id_t keyId;
#else
    mbedtls_gcm_context gcmCtx;
#endif
    bool initialized;
    bool hasKey;
} AesContext_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Initializes an AES-GCM context before key setup or data processing.
void aesInit(AesContext_t *ctx);
// Releases resources held by an AES-GCM context.
void aesDone(AesContext_t *ctx);

// Loads the encryption key into an AES-GCM context.
esp_err_t aesSetKey(AesContext_t *ctx, const uint8_t *key, size_t keyLen);

// Encrypts a buffer with AES-GCM and appends the authentication tag.
// Size of ciphertextOut must be plaintextLen plus 16 bytes for tag
esp_err_t aesEncrypt(AesContext_t *ctx, const uint8_t *plaintext, size_t plaintextLen, const uint8_t *iv, size_t ivLen,
                      const uint8_t *aad, size_t aadLen, uint8_t *ciphertextOut);
// Decrypts and authenticates a buffer produced by AES-GCM.
// Size of plaintextOut will be ciphertextLen minus 16 bytes because ciphertext must include
// the tag at the end
esp_err_t aesDecrypt(AesContext_t *ctx, const uint8_t *ciphertext, size_t ciphertextLen, const uint8_t *iv, size_t ivLen,
                      const uint8_t *aad, size_t aadLen, uint8_t *plaintextOut);

#ifdef __cplusplus
}
#endif // __cplusplus
