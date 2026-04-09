#include "iot_comm/crypto/aes.h"
#include <assert.h>
#include <string.h>

// static const char* TAG = "AES";

#define GCM_TAG_LEN 16

// -----------------------------------------------------------------------------

#if ESP_IDF_VERSION_MAJOR >= 6
static psa_status_t importAesKey(psa_key_id_t *keyId, const uint8_t *key, size_t keyLen);
#endif

// -----------------------------------------------------------------------------

void aesInit(AesContext_t *ctx)
{
    assert(ctx);
#if ESP_IDF_VERSION_MAJOR >= 6
    ctx->keyId = PSA_KEY_ID_NULL;
#else
    mbedtls_gcm_init(&ctx->gcmCtx);
#endif
    ctx->initialized = true;
    ctx->hasKey = false;
}

void aesDone(AesContext_t *ctx)
{
    assert(ctx);

    if (!ctx->initialized) {
        return;
    }

#if ESP_IDF_VERSION_MAJOR >= 6
    if (ctx->hasKey) {
        psa_destroy_key(ctx->keyId);
        ctx->keyId = PSA_KEY_ID_NULL;
    }
#else
    mbedtls_gcm_free(&ctx->gcmCtx);
#endif

    ctx->initialized = false;
    ctx->hasKey = false;
}

esp_err_t aesSetKey(AesContext_t *ctx, const uint8_t *key, size_t keyLen)
{
    esp_err_t err;

    assert(ctx);

    if ((!key) || keyLen == 0 || keyLen > 32) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!ctx->initialized) {
        return ESP_ERR_INVALID_STATE;
    }

#if ESP_IDF_VERSION_MAJOR >= 6
    if (ctx->hasKey) {
        psa_destroy_key(ctx->keyId);
        ctx->keyId = PSA_KEY_ID_NULL;
        ctx->hasKey = false;
    }

    err = importAesKey(&ctx->keyId, key, keyLen);
    if (err != ESP_OK) {
        return err;
    }
#else
    err = mbedtls_gcm_setkey(&ctx->gcmCtx, MBEDTLS_CIPHER_ID_AES, key, keyLen * 8);
    if (err != ESP_OK) {
        return err;
    }
#endif

    ctx->hasKey = true;
    return ESP_OK;
}

esp_err_t aesEncrypt(AesContext_t *ctx, const uint8_t *plaintext, size_t plaintextLen, const uint8_t *iv, size_t ivLen,
                     const uint8_t *aad, size_t aadLen, uint8_t *ciphertextOut)
{
#if ESP_IDF_VERSION_MAJOR >= 6
    size_t ciphertextLen = 0;
    psa_status_t status;
#else
    uint8_t tag[GCM_TAG_LEN];
    esp_err_t err;
#endif

    assert(ctx);

    if ((!ctx->initialized) || (!ctx->hasKey)) {
        return ESP_ERR_INVALID_STATE;
    }

#if ESP_IDF_VERSION_MAJOR >= 6
    status = psa_aead_encrypt(ctx->keyId, PSA_ALG_GCM, iv, ivLen, aad, aadLen, plaintext, plaintextLen, ciphertextOut,
                              plaintextLen + GCM_TAG_LEN, &ciphertextLen);
    if (status != PSA_SUCCESS) {
        return status;
    }
    return (ciphertextLen == plaintextLen + GCM_TAG_LEN) ? ESP_OK : ESP_FAIL;
#else
    err = mbedtls_gcm_crypt_and_tag(&ctx->gcmCtx, MBEDTLS_GCM_ENCRYPT, plaintextLen, iv, ivLen, aad, aadLen, plaintext, ciphertextOut,
                                    GCM_TAG_LEN, tag);
    if (err == ESP_OK) {
        memcpy(ciphertextOut + plaintextLen, tag, GCM_TAG_LEN);
    }
    return err;
#endif
}

esp_err_t aesDecrypt(AesContext_t *ctx, const uint8_t *ciphertext, size_t ciphertextLen, const uint8_t *iv, size_t ivLen,
                     const uint8_t *aad, size_t aadLen, uint8_t *plaintextOut)
{
#if ESP_IDF_VERSION_MAJOR >= 6
    psa_status_t status;
    size_t plaintextLen;
#else
    esp_err_t err;
#endif

    assert(ctx);

    if ((!ctx->initialized) || (!ctx->hasKey)) {
        return ESP_ERR_INVALID_STATE;
    }

    if (ciphertextLen < GCM_TAG_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    ciphertextLen -= GCM_TAG_LEN;

#if ESP_IDF_VERSION_MAJOR >= 6
    status = psa_aead_decrypt(ctx->keyId, PSA_ALG_GCM, iv, ivLen, aad, aadLen, ciphertext, ciphertextLen + GCM_TAG_LEN, plaintextOut,
                              ciphertextLen, &plaintextLen);
    if (status != PSA_SUCCESS) {
        return status;
    }
    return (plaintextLen == ciphertextLen) ? ESP_OK : ESP_FAIL;
#else
    err = mbedtls_gcm_auth_decrypt(&ctx->gcmCtx, ciphertextLen, iv, ivLen, aad, aadLen, ciphertext + ciphertextLen, GCM_TAG_LEN,
                                   ciphertext, plaintextOut);
    return err;
#endif
}

#if ESP_IDF_VERSION_MAJOR >= 6
static psa_status_t importAesKey(psa_key_id_t *keyId, const uint8_t *key, size_t keyLen)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS && status != PSA_ERROR_BAD_STATE) {
        return status;
    }

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, (size_t)(keyLen * 8));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    status = psa_import_key(&attr, key, keyLen, keyId);
    psa_reset_key_attributes(&attr);
    return status;
}
#endif
