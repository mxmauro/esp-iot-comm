#include "iot_comm/crypto/p256.h"
#include "iot_comm/crypto/utils.h"
#include <assert.h>
#include <convert.h>
#include <esp_log.h>
#include <mbedtls/ecdsa.h>
#include <mutex.h>

static const char* TAG = "P-256";

// -----------------------------------------------------------------------------

static Mutex initMtx;
static bool initialized = false;

static mbedtls_ecp_group ecpGroup = {};

// -----------------------------------------------------------------------------

#define DELAYED_P256_INIT()     \
    {                           \
        esp_err_t err = init(); \
        if (err != ESP_OK) {    \
            return err;         \
        }                       \
    }

// -----------------------------------------------------------------------------

static esp_err_t init();
static int randomGen(void *ctx, unsigned char *dest, size_t count);

// -----------------------------------------------------------------------------

void p256KeyPairInit(P256KeyPair_t *pair)
{
    assert(pair);

    mbedtls_mpi_init(&pair->d);
    mbedtls_ecp_point_init(&pair->q);
}

void p256KeyPairDone(P256KeyPair_t *pair)
{
    assert(pair);

    mbedtls_mpi_free(&pair->d);
    mbedtls_ecp_point_free(&pair->q);
}

esp_err_t p256LoadPublicKey(P256KeyPair_t *pair, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE])
{
    assert(pair);

    DELAYED_P256_INIT();

    mbedtls_ecp_point_free(&pair->q);
    mbedtls_ecp_point_init(&pair->q);
    return mbedtls_ecp_point_read_binary(&ecpGroup, &pair->q, publicKey, P256_PUBLIC_KEY_SIZE);
}

esp_err_t p256SavePublicKey(P256KeyPair_t *pair, uint8_t publicKey[P256_PUBLIC_KEY_SIZE])
{
    size_t outLen;

    assert(pair);

    DELAYED_P256_INIT();

    return mbedtls_ecp_point_write_binary(&ecpGroup, &pair->q, MBEDTLS_ECP_PF_UNCOMPRESSED, &outLen, publicKey, P256_PUBLIC_KEY_SIZE);
}

esp_err_t p256LoadPrivateKey(P256KeyPair_t *pair, const uint8_t privateKey[P256_PRIVATE_KEY_SIZE])
{
    assert(pair);

    DELAYED_P256_INIT();

    mbedtls_mpi_free(&pair->d);
    mbedtls_mpi_init(&pair->d);
    return mbedtls_mpi_read_binary(&pair->d, privateKey, P256_PRIVATE_KEY_SIZE);
}

esp_err_t p256SavePrivateKey(P256KeyPair_t *pair, uint8_t privateKey[P256_PRIVATE_KEY_SIZE])
{
    assert(pair);

    DELAYED_P256_INIT();

    return mbedtls_mpi_write_binary(&pair->d, privateKey, P256_PRIVATE_KEY_SIZE);
}

esp_err_t p256LoadPublicKeyB64(P256KeyPair_t *pair, const char *publicKey, size_t publicKeyLen, bool isUrl)
{
    uint8_t buffer[P256_PUBLIC_KEY_SIZE];
    size_t decodedLen;

    assert(pair);

    decodedLen = sizeof(buffer);
    if (!fromB64(publicKey, publicKeyLen, isUrl, buffer, &decodedLen)) {
        ESP_LOGE(TAG, "Unable to decode base64 public key");
        return ESP_FAIL;
    }
    if (decodedLen != P256_PUBLIC_KEY_SIZE) {
        ESP_LOGE(TAG, "Invalid public key size: %d", decodedLen);
        return ESP_ERR_INVALID_SIZE;
    }
    return p256LoadPublicKey(pair, buffer);
}

esp_err_t p256SavePublicKeyB64(P256KeyPair_t *pair, char *publicKey, size_t *publicKeyLen, bool isUrl)
{
    uint8_t buffer[P256_PUBLIC_KEY_SIZE];
    esp_err_t err;

    assert(pair);

    err = p256SavePublicKey(pair, buffer);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to save public key. Error: %d", err);
        *publicKeyLen = 0;
        return err;
    }
    if (!toB64(buffer, sizeof(buffer), isUrl, publicKey, publicKeyLen)) {
        ESP_LOGE(TAG, "Unable to encode base64 public key");
        *publicKeyLen = 0;
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t p256LoadPrivateKeyB64(P256KeyPair_t *pair, const char *privateKey, size_t privateKeyLen, bool isUrl)
{
    uint8_t buffer[P256_PRIVATE_KEY_SIZE];
    size_t decodedLen;
    esp_err_t err;

    assert(pair);

    decodedLen = sizeof(buffer);
    if (!fromB64(privateKey, privateKeyLen, isUrl, buffer, &decodedLen)) {
        ESP_LOGE(TAG, "Unable to decode base64 private key");
        return ESP_FAIL;
    }
    if (decodedLen == P256_PRIVATE_KEY_SIZE) {
        err = p256LoadPrivateKey(pair, buffer);
    }
    else {
        ESP_LOGE(TAG, "Invalid private key size: %d", decodedLen);
        err = ESP_ERR_INVALID_SIZE;
    }
    memset(buffer, 0, sizeof(buffer));
    return err;
}

esp_err_t p256SavePrivateKeyB64(P256KeyPair_t *pair, char *privateKey, size_t *privateKeyLen, bool isUrl)
{
    uint8_t buffer[P256_PRIVATE_KEY_SIZE];
    esp_err_t err;

    assert(pair);

    err = p256SavePrivateKey(pair, buffer);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to save private key. Error: %d", err);
        *privateKeyLen = 0;
        return err;
    }
    if (!toB64(buffer, sizeof(buffer), isUrl, privateKey, privateKeyLen)) {
        ESP_LOGE(TAG, "Unable to encode base64 private key");
        *privateKeyLen = 0;
        err = ESP_FAIL;
    }
    memset(buffer, 0, sizeof(buffer));
    return err;
}

bool p256ValidatePublicKey(const uint8_t *publicKey, size_t publicKeySize)
{
    uint8_t tempPk[P256_PUBLIC_KEY_SIZE];
    P256KeyPair_t pair;
    bool ret;

    if ((!publicKey) || publicKeySize != P256_PUBLIC_KEY_SIZE) {
        return false;
    }

    memcpy(tempPk, publicKey, P256_PUBLIC_KEY_SIZE);

    p256KeyPairInit(&pair);
    ret = (p256LoadPublicKey(&pair, tempPk) == ESP_OK) ? true : false;
    p256KeyPairDone(&pair);

    memset(tempPk, 0, sizeof(tempPk));
    return ret;
}

// -----------------------------------------------------------------------------

esp_err_t ecdhGeneratePair(P256KeyPair_t *pair)
{
    esp_err_t err;

    assert(pair);

    DELAYED_P256_INIT();

    // mbedtls_ecdh_gen_public is used despite its name because it will generate both
    // private and public keys in this scenario.
    err = mbedtls_ecdh_gen_public(&ecpGroup, &pair->d, &pair->q, randomGen, nullptr);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to generate ECDH keys. Error: %d", err);
        return err;
    }

    // Done
    return ESP_OK;
}

esp_err_t ecdhComputeSharedSecret(P256KeyPair_t *pair, uint8_t sharedSecret[P256_SHARED_SECRET_SIZE])
{
    mbedtls_mpi temp;
    esp_err_t err;

    assert(pair);

    DELAYED_P256_INIT();

    mbedtls_mpi_init(&temp);
    err = mbedtls_ecdh_compute_shared(&ecpGroup, &temp, &pair->q, &pair->d, randomGen, nullptr);
    if (err == ESP_OK) {
        err = mbedtls_mpi_write_binary(&temp, sharedSecret, P256_SHARED_SECRET_SIZE);
    }
    mbedtls_mpi_free(&temp);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to compute shared secret. Error: %d", err);
        return err;
    }

    // Done
    return ESP_OK;
}

// -----------------------------------------------------------------------------

esp_err_t ecdsaGeneratePair(P256KeyPair_t *pair)
{
    esp_err_t err;

    assert(pair);

    DELAYED_P256_INIT();

    err = mbedtls_ecp_gen_keypair(&ecpGroup, &pair->d, &pair->q, randomGen, nullptr);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to generate ECDSA keys. Error: %d", err);
        return err;
    }

    // Done
    return ESP_OK;
}

esp_err_t ecdsaSign(P256KeyPair_t *pair, const uint8_t hash[P256_HASH_SIZE], uint8_t signature[P256_SIGNATURE_SIZE])
{
    mbedtls_mpi r, s;
    esp_err_t err;

    assert(pair);

    DELAYED_P256_INIT();

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    err = mbedtls_ecdsa_sign(&ecpGroup, &r, &s, &pair->d, hash, P256_HASH_SIZE, randomGen, nullptr);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to sign hash. Error: %d", err);
        goto cleanup;
    }
    err = mbedtls_mpi_write_binary(&r, signature, P256_SIGNATURE_SIZE / 2);
    if (err == ESP_OK) {
        err = mbedtls_mpi_write_binary(&s, signature + P256_SIGNATURE_SIZE / 2, P256_SIGNATURE_SIZE / 2);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to write signature. Error: %d", err);
        goto cleanup;
    }

    // Done
    err = ESP_OK;

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return err;
}

esp_err_t ecdsaVerify(P256KeyPair_t *pair, const uint8_t hash[P256_HASH_SIZE], const uint8_t signature[P256_SIGNATURE_SIZE])
{
    mbedtls_mpi r, s;
    esp_err_t err;

    assert(pair);

    DELAYED_P256_INIT();

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    err = mbedtls_mpi_read_binary(&r, signature, P256_SIGNATURE_SIZE / 2);
    if (err == ESP_OK) {
        err = mbedtls_mpi_read_binary(&s, signature + P256_SIGNATURE_SIZE / 2, P256_SIGNATURE_SIZE / 2);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to read signature. Error: %d", err);
        goto cleanup;
    }
    err = mbedtls_ecdsa_verify(&ecpGroup, hash, P256_HASH_SIZE, &pair->q, &r, &s);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Signature verification failed. Error: %d", err);
        goto cleanup;
    }

    // Done
    err = ESP_OK;
cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return err;
}

// -----------------------------------------------------------------------------

static esp_err_t init()
{
    AutoMutex lock(initMtx);

    if (!initialized) {
        esp_err_t err;

        mbedtls_ecp_group_init(&ecpGroup);
        err = mbedtls_ecp_group_load(&ecpGroup, MBEDTLS_ECP_DP_SECP256R1);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to load ECP group. Error: %d", err);
            mbedtls_ecp_group_free(&ecpGroup);
            return err;
        }

        initialized = true;
    }

    // Done
    return ESP_OK;
}

static int randomGen(void *ctx, unsigned char *dest, size_t count)
{
    return (int)randomize((uint8_t *)dest, count);
}
