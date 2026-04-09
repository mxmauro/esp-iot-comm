#pragma once

#include <esp_err.h>
#include <esp_idf_version.h>
#include <stdbool.h>
#include <stdint.h>

#if ESP_IDF_VERSION_MAJOR >= 6
    #include <psa/crypto.h>
#else
    #include <mbedtls/sha256.h>
    #include <mbedtls/sha512.h>
#endif

#define SHA256_SIZE 32
#define SHA512_SIZE 64

// -----------------------------------------------------------------------------

#if ESP_IDF_VERSION_MAJOR >= 6
typedef struct Sha256Context_s {
    psa_hash_operation_t op;
    bool                 initialized;
    bool                 active;
} Sha256Context_t;

typedef struct Sha512Context_s {
    psa_hash_operation_t op;
    bool                 initialized;
    bool                 active;
} Sha512Context_t;
#else
typedef mbedtls_sha256_context Sha256Context_t;
typedef mbedtls_sha512_context Sha512Context_t;
#endif

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void sha256Init(Sha256Context_t *ctx);
void sha256Done(Sha256Context_t *ctx);
esp_err_t sha256Start(Sha256Context_t *ctx);
esp_err_t sha256Update(Sha256Context_t *ctx, const uint8_t *data, size_t len);
esp_err_t sha256Finish(Sha256Context_t *ctx, uint8_t out[SHA256_SIZE]);

void sha512Init(Sha512Context_t *ctx);
void sha512Done(Sha512Context_t *ctx);
esp_err_t sha512Start(Sha512Context_t *ctx);
esp_err_t sha512Update(Sha512Context_t *ctx, const uint8_t *data, size_t len);
esp_err_t sha512Finish(Sha512Context_t *ctx, uint8_t out[SHA512_SIZE]);

#ifdef __cplusplus
}
#endif // __cplusplus
