#include "iot_comm/crypto/aes.h"
#include <assert.h>
#include <string.h>

// static const char* TAG = "AES";

#define GCM_TAG_LEN 16

// -----------------------------------------------------------------------------

void aesInit(mbedtls_gcm_context *ctx)
{
    assert(ctx);
    mbedtls_gcm_init(ctx);
}

void aesDone(mbedtls_gcm_context *ctx)
{
    assert(ctx);
    mbedtls_gcm_free(ctx);
}

esp_err_t aesSetKey(mbedtls_gcm_context *ctx, const uint8_t *key, size_t keyLen)
{
    assert(ctx);
    return mbedtls_gcm_setkey(ctx, MBEDTLS_CIPHER_ID_AES, key, keyLen * 8);
}

esp_err_t aesEncrypt(mbedtls_gcm_context *ctx, const uint8_t *plaintext, size_t plaintextLen, const uint8_t *iv, size_t ivLen,
                     const uint8_t *aad, size_t aadLen, uint8_t *ciphertextOut)
{
    uint8_t tag[GCM_TAG_LEN];
    esp_err_t err;

    assert(ctx);
    err = mbedtls_gcm_crypt_and_tag(ctx, MBEDTLS_GCM_ENCRYPT, plaintextLen, iv, ivLen, aad, aadLen, plaintext, ciphertextOut, GCM_TAG_LEN,
                                    tag);
    if (err == ESP_OK) {
        memcpy(ciphertextOut + plaintextLen, tag, GCM_TAG_LEN);
    }
    return err;
}

esp_err_t aesDecrypt(mbedtls_gcm_context *ctx, const uint8_t *ciphertext, size_t ciphertextLen, const uint8_t *iv, size_t ivLen,
                     const uint8_t *aad, size_t aadLen, uint8_t *plaintextOut)
{
    assert(ctx);

    if (ciphertextLen < GCM_TAG_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    ciphertextLen -= GCM_TAG_LEN;
    return mbedtls_gcm_auth_decrypt(ctx, ciphertextLen, iv, ivLen, aad, aadLen, ciphertext + ciphertextLen, GCM_TAG_LEN, ciphertext,
                                    plaintextOut);
}
