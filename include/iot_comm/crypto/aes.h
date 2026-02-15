#pragma once

#include "sdkconfig.h"
#include <esp_err.h>
#include <mbedtls/gcm.h>
#include <stdint.h>

#if (!defined(CONFIG_MBEDTLS_AES_C)) || (!defined(CONFIG_MBEDTLS_GCM_C))
    #error This library requires CONFIG_MBEDTLS_AES_C and CONFIG_MBEDTLS_GCM_C to be enabled
#endif

// -----------------------------------------------------------------------------

#ifndef __cplusplus
    #error C++ compiler required.
#endif // !__cplusplus

class Aes
{
public:
    Aes();
    ~Aes();

    esp_err_t setKey(const uint8_t *key, size_t keyLen);

    // Size of ciphertextOut must be plaintextLen plus 16 bytes for tag
    esp_err_t encrypt(const uint8_t *plaintext, size_t plaintextLen, const uint8_t *iv, size_t ivLen,
                      const uint8_t *aad, size_t aadLen, uint8_t *ciphertextOut);
    // Size of plaintextOut will be ciphertextLen minus 16 bytes because ciphertext must include the tag at the end
    esp_err_t decrypt(const uint8_t *ciphertext, size_t ciphertextLen, const uint8_t *iv, size_t ivLen,
                      const uint8_t *aad, size_t aadLen, uint8_t *plaintextOut);

private:
    mbedtls_gcm_context gcm;
    bool valid;
};
