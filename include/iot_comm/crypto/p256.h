#pragma once

#include "sdkconfig.h"
#include <esp_err.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/pk.h>
#include <stdint.h>

#if (!defined(CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED)) || (!defined(CONFIG_MBEDTLS_HKDF_C))
    #error This library requires CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED and CONFIG_MBEDTLS_HKDF_C to be enabled
#endif

#if (!defined(CONFIG_MBEDTLS_PK_PARSE_EC_EXTENDED)) || (!defined(CONFIG_MBEDTLS_PK_PARSE_EC_COMPRESSED))
    #error This library requires CONFIG_MBEDTLS_PK_PARSE_EC_EXTENDED and CONFIG_MBEDTLS_PK_PARSE_EC_COMPRESSED to be enabled
#endif

#if (!defined(CONFIG_MBEDTLS_ECDH_C)) || (!defined(CONFIG_MBEDTLS_ECDSA_C))
    #error This library requires CONFIG_MBEDTLS_ECDH_C and CONFIG_MBEDTLS_ECDSA_C to be enabled
#endif

#define P256_PUBLIC_KEY_SIZE  65
#define P256_PRIVATE_KEY_SIZE 32

#define P256_MAX_B64_PUBLIC_KEY_SIZE  89 // One extra for nul terminator
#define P256_MAX_B64_PRIVATE_KEY_SIZE 45 // One extra for nul terminator

#define P256_SHARED_SECRET_SIZE 32

#define P256_HASH_SIZE      32
#define P256_SIGNATURE_SIZE 64

// -----------------------------------------------------------------------------

// Stores a P-256 private key together with its public point.
typedef struct P256KeyPair_s {
    mbedtls_mpi       d; // Private key
    mbedtls_ecp_point q; // Public key
} P256KeyPair_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Initializes a P-256 key pair container.
void p256KeyPairInit(P256KeyPair_t *pair);
// Releases resources held by a P-256 key pair container.
void p256KeyPairDone(P256KeyPair_t *pair);

// Loads a raw uncompressed public key into a key pair container.
esp_err_t p256LoadPublicKey(P256KeyPair_t *pair, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);
// Exports the public key from a key pair container in raw form.
esp_err_t p256SavePublicKey(P256KeyPair_t *pair, uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);

// Loads a raw private key into a key pair container.
esp_err_t p256LoadPrivateKey(P256KeyPair_t *pair, const uint8_t privateKey[P256_PRIVATE_KEY_SIZE]);
// Exports the private key from a key pair container in raw form.
esp_err_t p256SavePrivateKey(P256KeyPair_t *pair, uint8_t privateKey[P256_PRIVATE_KEY_SIZE]);

// Loads a base64-encoded public key into a key pair container.
esp_err_t p256LoadPublicKeyB64(P256KeyPair_t *pair, const char *publicKey, size_t publicKeyLen, bool isUrl);
// On input, publicKeyLen is the size of the buffer.
// On output, publicKeyLen is the size of the written data.
// Exports the public key from a key pair container using base64 encoding.
esp_err_t p256SavePublicKeyB64(P256KeyPair_t *pair, char *publicKey, size_t *publicKeyLen, bool isUrl);

// Loads a base64-encoded private key into a key pair container.
esp_err_t p256LoadPrivateKeyB64(P256KeyPair_t *pair, const char *privateKey, size_t privateKeyLen, bool isUrl);
// On input, publicKeyLen is the size of the buffer.
// On output, publicKeyLen is the size of the written data.
// Exports the private key from a key pair container using base64 encoding.
esp_err_t p256SavePrivateKeyB64(P256KeyPair_t *pair, char *privateKey, size_t *privateKeyLen, bool isUrl);

// Verifies that a raw public key is a valid P-256 point.
bool p256ValidatePublicKey(const uint8_t *publicKey, size_t publicKeySize);

// Generates an ECDH key pair on the P-256 curve.
esp_err_t ecdhGeneratePair(P256KeyPair_t *pair);

// Computes the shared secret for an initialized ECDH key pair.
esp_err_t ecdhComputeSharedSecret(P256KeyPair_t *pair, uint8_t sharedSecret[P256_SHARED_SECRET_SIZE]);

// Generates an ECDSA signing key pair on the P-256 curve.
esp_err_t ecdsaGeneratePair(P256KeyPair_t *pair);

// Signs a fixed-size hash with the private key in the pair.
esp_err_t ecdsaSign(P256KeyPair_t *pair, const uint8_t hash[P256_HASH_SIZE], uint8_t signature[P256_SIGNATURE_SIZE]);
// Verifies a signature against a fixed-size hash with the public key in the pair.
esp_err_t ecdsaVerify(P256KeyPair_t *pair, const uint8_t hash[P256_HASH_SIZE], const uint8_t signature[P256_SIGNATURE_SIZE]);

#ifdef __cplusplus
}
#endif // __cplusplus
