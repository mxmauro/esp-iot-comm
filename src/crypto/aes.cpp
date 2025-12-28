#include "iot_comm/crypto/aes.h"
#include <string.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>

// static const char* TAG = "AES";

#define GCM_TAG_LEN 16

// -----------------------------------------------------------------------------

esp_err_t aesDeriveKey(const uint8_t *key, size_t keyLen, const uint8_t *salt, size_t saltLen,
                       const uint8_t *info, size_t infoLen, uint8_t *keyOut, size_t keyOutLen)
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_hkdf(md, salt, saltLen, key, keyLen, info, infoLen, keyOut, keyOutLen);
}

esp_err_t aesEncrypt(const uint8_t *key, size_t keyLen, const uint8_t *plaintext, size_t plaintextLen,
                     const uint8_t *iv, size_t ivLen, const uint8_t *aad, size_t aadLen, uint8_t *ciphertextOut)
{
    mbedtls_gcm_context gcm;
    uint8_t tag[GCM_TAG_LEN];
    esp_err_t err;

    mbedtls_gcm_init(&gcm);
    err = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, keyLen * 8);
    if (err != ESP_OK) {
        mbedtls_gcm_free(&gcm);
        return err;
    }
    err = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintextLen, iv, ivLen, aad, aadLen,
                                    plaintext, ciphertextOut, GCM_TAG_LEN, tag);
    if (err == ESP_OK) {
        memcpy(ciphertextOut + plaintextLen, tag, GCM_TAG_LEN);
    }
    mbedtls_gcm_free(&gcm);
    return err;
}

esp_err_t aesDecrypt(const uint8_t *key, size_t keyLen, const uint8_t *ciphertext, size_t ciphertextLen,
                     const uint8_t *iv, size_t ivLen, const uint8_t *aad, size_t aadLen, uint8_t *plaintextOut)
{
    mbedtls_gcm_context gcm;
    esp_err_t err;

    if (ciphertextLen < GCM_TAG_LEN) {
        return ESP_ERR_INVALID_ARG;
    }
    ciphertextLen -= GCM_TAG_LEN;

    mbedtls_gcm_init(&gcm);
    err = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, keyLen * 8);
    if (err != ESP_OK) {
        mbedtls_gcm_free(&gcm);
        return err;
    }
    err = mbedtls_gcm_auth_decrypt(&gcm, ciphertextLen, iv, ivLen, aad, aadLen, ciphertext + ciphertextLen,
                                GCM_TAG_LEN, ciphertext, plaintextOut);
    mbedtls_gcm_free(&gcm);
    return err;
}
