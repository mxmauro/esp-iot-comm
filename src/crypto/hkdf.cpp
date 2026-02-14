#include "iot_comm/crypto/hkdf.h"
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

// static const char* TAG = "HKDF";

// -----------------------------------------------------------------------------

esp_err_t hkdfSha256DeriveKey(const uint8_t *key, size_t keyLen, const uint8_t *salt, size_t saltLen,
                              const uint8_t *info, size_t infoLen, uint8_t *keyOut, size_t keyOutLen)
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_hkdf(md, salt, saltLen, key, keyLen, info, infoLen, keyOut, keyOutLen);
}
