#pragma once

#include "sdkconfig.h"
#include <esp_err.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/pk.h>

#if (!defined(CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED)) || (!defined(CONFIG_MBEDTLS_HKDF_C))
    #error This library requires CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED and CONFIG_MBEDTLS_HKDF_C to be enabled
#endif

#if (!defined(CONFIG_MBEDTLS_PK_PARSE_EC_EXTENDED)) || (!defined(CONFIG_MBEDTLS_PK_PARSE_EC_COMPRESSED))
    #error This library requires CONFIG_MBEDTLS_PK_PARSE_EC_EXTENDED and CONFIG_MBEDTLS_PK_PARSE_EC_COMPRESSED to be enabled
#endif

#if (!defined(CONFIG_MBEDTLS_ECDH_C)) || (!defined(CONFIG_MBEDTLS_ECDSA_C))
    #error This library requires CONFIG_MBEDTLS_ECDH_C and CONFIG_MBEDTLS_ECDSA_C to be enabled
#endif

#define P256_SHARED_SECRET_SIZE 32

#define P256_HASH_SIZE      32
#define P256_SIGNATURE_SIZE 64

#define P256_PUBLIC_KEY_SIZE  65
#define P256_PRIVATE_KEY_SIZE 32

#define P256_MAX_B64_PUBLIC_KEY_SIZE  89 // One extra for nul terminator
#define P256_MAX_B64_PRIVATE_KEY_SIZE 45 // One extra for nul terminator

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t p256Init();
void p256Done();

bool randomize(uint8_t *dest, size_t destLen);

bool constantTimeCompare(const void *buf1, const void *buf2, size_t len);

#ifdef __cplusplus
};
#endif // __cplusplus

// -----------------------------------------------------------------------------

#ifdef __cplusplus

// P256KeyPair is a base class for P-256 key pairs.
class P256KeyPair
{
public:
    P256KeyPair();
    ~P256KeyPair();

    esp_err_t loadPublicKey(const uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);
    esp_err_t savePublicKey(uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);

    esp_err_t loadPrivateKey(const uint8_t privateKey[P256_PRIVATE_KEY_SIZE]);
    esp_err_t savePrivateKey(uint8_t privateKey[P256_PRIVATE_KEY_SIZE]);

    esp_err_t loadPublicKeyB64(const char *publicKey, size_t publicKeyLen, bool isUrl);
    // On input, publicKeyLen is the size of the buffer.
    // On output, publicKeyLen is the size of the written data.
    esp_err_t savePublicKeyB64(char *publicKey, size_t *publicKeyLen, bool isUrl);

    esp_err_t loadPrivateKeyB64(const char *privateKey, size_t privateKeyLen, bool isUrl);
    // On input, publicKeyLen is the size of the buffer.
    // On output, publicKeyLen is the size of the written data.
    esp_err_t savePrivateKeyB64(char *privateKey, size_t *privateKeyLen, bool isUrl);

    static bool validatePublicKey(const uint8_t *publicKey, size_t publicKeySize);

protected:
    void reset();

protected:
    mbedtls_mpi d; // Private key
    mbedtls_ecp_point q; // Public key
};

// ECDHKeyPair represents a P-256 key pair for ECDH operations.
class ECDHKeyPair : public P256KeyPair
{
public:
    esp_err_t generate();

    esp_err_t computeSharedSecret(uint8_t sharedSecret[P256_SHARED_SECRET_SIZE]);
};

// ECDSAKeyPair represents a P-256 key pair for ECDSA operations.
class ECDSAKeyPair : public P256KeyPair
{
public:
    esp_err_t generate();

    esp_err_t sign(const uint8_t hash[P256_HASH_SIZE], uint8_t signature[P256_SIGNATURE_SIZE]);
    esp_err_t verify(const uint8_t hash[P256_HASH_SIZE], const uint8_t signature[P256_SIGNATURE_SIZE]);
};

#endif // __cplusplus
