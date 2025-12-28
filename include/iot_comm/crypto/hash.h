#pragma once

#include "sdkconfig.h"
#include <esp_err.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#if (!defined(CONFIG_MBEDTLS_HKDF_C)) || (!defined(CONFIG_MBEDTLS_AES_C)) || (!defined(CONFIG_MBEDTLS_GCM_C))
    #error This library requires CONFIG_MBEDTLS_HKDF_C, CONFIG_MBEDTLS_AES_C and CONFIG_MBEDTLS_GCM_C to be enabled
#endif

#define SHA256_SIZE 32

// -----------------------------------------------------------------------------

#ifndef __cplusplus
    #error C++ compiler required.
#endif // !__cplusplus

class Sha256
{
public:
    Sha256();
    ~Sha256();

    void init();
    void update(const void *data, size_t dataLen);
    void finalize(uint8_t hash[SHA256_SIZE]);

    esp_err_t error() const
        {
            return err;
        };

private:
    mbedtls_sha256_context ctx;
    esp_err_t err;
};
