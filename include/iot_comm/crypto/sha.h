#pragma once

#include "iot_comm/crypto/ihash.h"
#include <esp_idf_version.h>
#include <memory.h>
#include <stdbool.h>
#include <stddef.h>
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

void sha256Init(Sha256Context_t* ctx);
void sha256Done(Sha256Context_t* ctx);
esp_err_t sha256Start(Sha256Context_t* ctx);
esp_err_t sha256Update(Sha256Context_t* ctx, const uint8_t* data, size_t len);
esp_err_t sha256Finish(Sha256Context_t* ctx, uint8_t out[SHA256_SIZE]);

void sha512Init(Sha512Context_t* ctx);
void sha512Done(Sha512Context_t* ctx);
esp_err_t sha512Start(Sha512Context_t* ctx);
esp_err_t sha512Update(Sha512Context_t* ctx, const uint8_t* data, size_t len);
esp_err_t sha512Finish(Sha512Context_t* ctx, uint8_t out[SHA512_SIZE]);

#ifdef __cplusplus
}
#endif // __cplusplus

// -----------------------------------------------------------------------------

#ifdef __cplusplus

class Sha256 : public IHash
{
public:
    Sha256() noexcept : IHash()
    {
        Init();
    }
    Sha256(const Sha256&) noexcept = delete;
    Sha256(Sha256&&) noexcept = delete;

    ~Sha256() noexcept
    {
        Deinit();
    }

    Sha256& operator=(const Sha256&) noexcept = delete;
    Sha256& operator=(Sha256&&) noexcept = delete;

    esp_err_t Start() noexcept final
    {
        Init();
        return sha256Start(&ctx);
    }

    esp_err_t Update(const uint8_t* data, size_t len) noexcept final
    {
        return sha256Update(&ctx, data, len);
    }

    esp_err_t Finish() noexcept final
    {
        return sha256Finish(&ctx, out);
    }

    Sha256Context_t& NativeHandle() noexcept
    {
        return ctx;
    }

    const uint8_t* Output() const noexcept final
    {
        return out;
    }

    size_t OutputSize() const noexcept final
    {
        return SHA256_SIZE;
    }

private:
    void Init() noexcept
    {
        memset(out, 0, sizeof(out));
        sha256Init(&ctx);
    }

    void Deinit() noexcept
    {
        sha256Done(&ctx);
        memset(out, 0, sizeof(out));
    }

private:
    Sha256Context_t ctx;
    uint8_t         out[SHA256_SIZE];
};

// -----------------------------------------------------------------------------

class Sha512 : public IHash
{
public:
    Sha512() noexcept : IHash()
    {
        Init();
    }
    Sha512(const Sha512&) noexcept = delete;
    Sha512(Sha512&&) noexcept = delete;

    ~Sha512() noexcept
    {
        Deinit();
    }

    Sha512& operator=(const Sha512&) noexcept = delete;
    Sha512& operator=(Sha512&&) noexcept = delete;

    esp_err_t Start() noexcept
    {
        Init();
        return sha512Start(&ctx);
    }

    esp_err_t Update(const uint8_t* data, size_t len) noexcept
    {
        return sha512Update(&ctx, data, len);
    }

    esp_err_t Finish() noexcept
    {
        return sha512Finish(&ctx, out);
    }

    Sha512Context_t& NativeHandle() noexcept
    {
        return ctx;
    }

    const uint8_t* Output() const noexcept final
    {
        return out;
    }

    size_t OutputSize() const noexcept final
    {
        return SHA512_SIZE;
    }

private:
    void Init() noexcept
    {
        memset(out, 0, sizeof(out));
        sha512Init(&ctx);
    }

    void Deinit() noexcept
    {
        sha512Done(&ctx);
        memset(out, 0, sizeof(out));
    }

private:
    Sha512Context_t ctx;
    uint8_t         out[SHA512_SIZE];
};

#endif // __cplusplus
