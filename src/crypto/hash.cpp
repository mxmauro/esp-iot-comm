#include "iot_comm/crypto/hash.h"
#include <mbedtls/pkcs5.h>

// -----------------------------------------------------------------------------

Sha256::Sha256()
{
    mbedtls_sha256_init(&ctx);
    err = mbedtls_sha256_starts(&ctx, 0);
}

Sha256::~Sha256()
{
    mbedtls_sha256_free(&ctx);
}

void Sha256::init()
{
    mbedtls_sha256_free(&ctx);
    mbedtls_sha256_init(&ctx);
    err = mbedtls_sha256_starts(&ctx, 0);
}

void Sha256::update(const void *data, size_t dataLen)
{
    if (err == ESP_OK) {
        err = mbedtls_sha256_update(&ctx, (const uint8_t *)data, dataLen);
    }
}

void Sha256::finalize(uint8_t hash[SHA256_SIZE])
{
    if (err == ESP_OK) {
        err = mbedtls_sha256_finish(&ctx, hash);
    }
}
