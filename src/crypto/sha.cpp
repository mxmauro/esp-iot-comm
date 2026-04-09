#include "iot_comm/crypto/sha.h"

// -----------------------------------------------------------------------------

#if ESP_IDF_VERSION_MAJOR >= 6
static esp_err_t hashStart(psa_hash_operation_t *op, bool *active, psa_algorithm_t alg);
static esp_err_t hashUpdate(psa_hash_operation_t *op, bool active, const uint8_t *data, size_t len);
static esp_err_t hashFinish(psa_hash_operation_t *op, bool *active, uint8_t *out, size_t outSize);
#endif

// -----------------------------------------------------------------------------

void sha256Init(Sha256Context_t *ctx)
{
#if ESP_IDF_VERSION_MAJOR >= 6
    ctx->op = PSA_HASH_OPERATION_INIT;
    ctx->initialized = true;
    ctx->active = false;
#else
    mbedtls_sha256_init(ctx);
#endif
}

void sha256Done(Sha256Context_t *ctx)
{
#if ESP_IDF_VERSION_MAJOR >= 6
    if (ctx->initialized) {
        psa_hash_abort(&ctx->op);
        ctx->initialized = false;
        ctx->active = false;
    }
#else
    mbedtls_sha256_free(ctx);
#endif
}

esp_err_t sha256Start(Sha256Context_t *ctx)
{
#if ESP_IDF_VERSION_MAJOR >= 6
    return hashStart(&ctx->op, &ctx->active, PSA_ALG_SHA_256);
#else
    return mbedtls_sha256_starts(ctx, 0);
#endif
}

esp_err_t sha256Update(Sha256Context_t *ctx, const uint8_t *data, size_t len)
{
#if ESP_IDF_VERSION_MAJOR >= 6
    return hashUpdate(&ctx->op, ctx->active, data, len);
#else
    return mbedtls_sha256_update(ctx, data, len);
#endif
}

esp_err_t sha256Finish(Sha256Context_t *ctx, uint8_t out[SHA256_SIZE])
{
#if ESP_IDF_VERSION_MAJOR >= 6
    return hashFinish(&ctx->op, &ctx->active, out, SHA256_SIZE);
#else
    return mbedtls_sha256_finish(ctx, out);
#endif
}

void sha512Init(Sha512Context_t *ctx)
{
#if ESP_IDF_VERSION_MAJOR >= 6
    ctx->op = PSA_HASH_OPERATION_INIT;
    ctx->initialized = true;
    ctx->active = false;
#else
    mbedtls_sha512_init(ctx);
#endif
}

void sha512Done(Sha512Context_t *ctx)
{
#if ESP_IDF_VERSION_MAJOR >= 6
    if (ctx->initialized) {
        psa_hash_abort(&ctx->op);
        ctx->initialized = false;
        ctx->active = false;
    }
#else
    mbedtls_sha512_free(ctx);
#endif
}

esp_err_t sha512Start(Sha512Context_t *ctx)
{
#if ESP_IDF_VERSION_MAJOR >= 6
    return hashStart(&ctx->op, &ctx->active, PSA_ALG_SHA_512);
#else
    return mbedtls_sha512_starts(ctx, 0);
#endif
}

esp_err_t sha512Update(Sha512Context_t *ctx, const uint8_t *data, size_t len)
{
#if ESP_IDF_VERSION_MAJOR >= 6
    return hashUpdate(&ctx->op, ctx->active, data, len);
#else
    return mbedtls_sha512_update(ctx, data, len);
#endif
}

esp_err_t sha512Finish(Sha512Context_t *ctx, uint8_t out[SHA512_SIZE])
{
#if ESP_IDF_VERSION_MAJOR >= 6
    return hashFinish(&ctx->op, &ctx->active, out, SHA512_SIZE);
#else
    return mbedtls_sha512_finish(ctx, out);
#endif
}

#if ESP_IDF_VERSION_MAJOR >= 6
static esp_err_t hashStart(psa_hash_operation_t *op, bool *active, psa_algorithm_t alg)
{
    psa_status_t status;

    status = psa_crypto_init();
    if ((status != PSA_SUCCESS) && (status != PSA_ERROR_BAD_STATE)) {
        return status;
    }
    if (*active) {
        psa_hash_abort(op);
        *active = false;
    }

    status = psa_hash_setup(op, alg);
    if (status == PSA_SUCCESS) {
        *active = true;
    }
    return status;
}

static esp_err_t hashUpdate(psa_hash_operation_t *op, bool active, const uint8_t *data, size_t len)
{
    if (!active) {
        return ESP_ERR_INVALID_STATE;
    }
    return psa_hash_update(op, data, len);
}

static esp_err_t hashFinish(psa_hash_operation_t *op, bool *active, uint8_t *out, size_t outSize)
{
    size_t outLen = 0;
    psa_status_t status;

    if (!*active) {
        return ESP_ERR_INVALID_STATE;
    }

    status = psa_hash_finish(op, out, outSize, &outLen);
    *active = false;
    if (status != PSA_SUCCESS) {
        return status;
    }
    return (outLen == outSize) ? ESP_OK : ESP_FAIL;
}
#endif
