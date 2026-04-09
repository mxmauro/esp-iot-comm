#include "iot_comm/crypto/hkdf.h"

#if ESP_IDF_VERSION_MAJOR >= 6
    #include <psa/crypto.h>
#else
    #include <mbedtls/hkdf.h>
    #include <mbedtls/md.h>
#endif

// static const char* TAG = "HKDF";

// -----------------------------------------------------------------------------

esp_err_t hkdfSha256DeriveKey(const uint8_t *key, size_t keyLen, const uint8_t *salt, size_t saltLen, const uint8_t *info, size_t infoLen,
                              uint8_t *keyOut, size_t keyOutLen)
{
#if ESP_IDF_VERSION_MAJOR >= 6
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status;

    status = psa_crypto_init();
    if ((status != PSA_SUCCESS) && (status != PSA_ERROR_BAD_STATE)) {
        return status;
    }

    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, saltLen);
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, key, keyLen);
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info, infoLen);
    }
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_output_bytes(&op, keyOut, keyOutLen);
    }

    psa_key_derivation_abort(&op);
    return status;
#else
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_hkdf(md, salt, saltLen, key, keyLen, info, infoLen, keyOut, keyOutLen);
#endif
}
