#include "iot_comm/crypto/aes.h"
#include <string.h>

// static const char* TAG = "AES";

#define GCM_TAG_LEN 16

// -----------------------------------------------------------------------------

Aes::Aes()
{
    valid = false;
}

Aes::~Aes()
{
    if (valid) {
        mbedtls_gcm_free(&gcm);
    }
}

esp_err_t Aes::setKey(const uint8_t *key, size_t keyLen)
{
    esp_err_t err;

    if (valid) {
        mbedtls_gcm_free(&gcm);
    }
    mbedtls_gcm_init(&gcm);
    err = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, keyLen * 8);
    if (err != ESP_OK) {
        mbedtls_gcm_free(&gcm);
        valid = false;
        return err;
    }

    valid = true;
    return ESP_OK;
}

esp_err_t Aes::encrypt(const uint8_t *plaintext, size_t plaintextLen, const uint8_t *iv, size_t ivLen,
                       const uint8_t *aad, size_t aadLen, uint8_t *ciphertextOut)
{
    uint8_t tag[GCM_TAG_LEN];
    esp_err_t err;

    if (!valid) {
        return ESP_ERR_INVALID_STATE;
    }
    err = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintextLen, iv, ivLen, aad, aadLen,
                                    plaintext, ciphertextOut, GCM_TAG_LEN, tag);
    if (err == ESP_OK) {
        memcpy(ciphertextOut + plaintextLen, tag, GCM_TAG_LEN);
    }
    return err;
}

esp_err_t Aes::decrypt(const uint8_t *ciphertext, size_t ciphertextLen, const uint8_t *iv, size_t ivLen,
                       const uint8_t *aad, size_t aadLen, uint8_t *plaintextOut)
{
    esp_err_t err;

    if (ciphertextLen < GCM_TAG_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!valid) {
        return ESP_ERR_INVALID_STATE;
    }

    ciphertextLen -= GCM_TAG_LEN;

    err = mbedtls_gcm_auth_decrypt(&gcm, ciphertextLen, iv, ivLen, aad, aadLen, ciphertext + ciphertextLen,
                                   GCM_TAG_LEN, ciphertext, plaintextOut);
    return err;
}
