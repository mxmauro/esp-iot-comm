#include "iot_comm/crypto/p256.h"
#include <convert.h>
#include <esp_log.h>
#include <time.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>

static const char* TAG = "P-256";

// -----------------------------------------------------------------------------

static mbedtls_entropy_context entropyCtx = {};
static mbedtls_ctr_drbg_context ctrDrbgCtx = {};
static mbedtls_ecp_group ecpGroup = {};

// -----------------------------------------------------------------------------

esp_err_t p256Init()
{
    char pers[10 + 30];
    esp_err_t err;

    mbedtls_entropy_init(&entropyCtx);
    mbedtls_ctr_drbg_init(&ctrDrbgCtx);
    mbedtls_ecp_group_init(&ecpGroup);
    err = mbedtls_ecp_group_load(&ecpGroup, MBEDTLS_ECP_DP_SECP256R1);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to load ECP group. Error: %d", err);
        return err;
    }

    snprintf(pers, sizeof(pers), "esp32_ecdh%llu", now_ms());
    err = mbedtls_ctr_drbg_seed(&ctrDrbgCtx, mbedtls_entropy_func, &entropyCtx,
                                (const unsigned char*)pers, strlen(pers));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to seed the random number generator. Error: %d", err);
        p256Done();
        return err;
    }

    // Done
    return ESP_OK;
}

void p256Done()
{
    mbedtls_ecp_group_free(&ecpGroup);
    mbedtls_ctr_drbg_free(&ctrDrbgCtx);
    mbedtls_entropy_free(&entropyCtx);
}

bool randomize(uint8_t *dest, size_t destLen)
{
    return !!(mbedtls_ctr_drbg_random(&ctrDrbgCtx, dest, destLen) == ESP_OK);
}

bool constantTimeCompare(const void *buf1, const void *buf2, size_t len)
{
    const uint8_t *b1 = (const uint8_t *)buf1;
    const uint8_t *b2 = (const uint8_t *)buf2;
    uint8_t diff = 0;

    while (len > 0) {
        diff |= (*b1) ^ (*b2);
        b1 += 1;
        b2 += 1;
        len -= 1;
    }
    return !!(diff == 0);
}

// -----------------------------------------------------------------------------

P256KeyPair::P256KeyPair()
{
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);
}

P256KeyPair::~P256KeyPair()
{
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q);
}

esp_err_t P256KeyPair::loadPublicKey(const uint8_t publicKey[P256_PUBLIC_KEY_SIZE])
{
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_point_init(&q);
    return mbedtls_ecp_point_read_binary(&ecpGroup, &q, publicKey, P256_PUBLIC_KEY_SIZE);
}

esp_err_t P256KeyPair::savePublicKey(uint8_t publicKey[P256_PUBLIC_KEY_SIZE])
{
    size_t outLen;

    return mbedtls_ecp_point_write_binary(&ecpGroup, &q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                        &outLen, publicKey, P256_PUBLIC_KEY_SIZE);
}

esp_err_t P256KeyPair::savePrivateKey(uint8_t privateKey[P256_PRIVATE_KEY_SIZE])
{
    return mbedtls_mpi_write_binary(&d, privateKey, P256_PRIVATE_KEY_SIZE);
}

esp_err_t P256KeyPair::loadPrivateKey(const uint8_t privateKey[P256_PRIVATE_KEY_SIZE])
{
    mbedtls_mpi_free(&d);
    mbedtls_mpi_init(&d);
    return mbedtls_mpi_read_binary(&d, privateKey, P256_PRIVATE_KEY_SIZE);
}

esp_err_t P256KeyPair::loadPublicKeyB64(const char *publicKey, size_t publicKeyLen, bool isUrl)
{
    uint8_t buffer[P256_PUBLIC_KEY_SIZE];
    size_t decodedLen;

    decodedLen = sizeof(buffer);
    if (!fromB64(publicKey, publicKeyLen, isUrl, buffer, &decodedLen)) {
        ESP_LOGE(TAG, "Unable to decode base64 public key");
        return ESP_FAIL;
    }
    if (decodedLen != P256_PUBLIC_KEY_SIZE) {
        ESP_LOGE(TAG, "Invalid public key size: %d", decodedLen);
        return ESP_ERR_INVALID_SIZE;
    }
    return loadPublicKey(buffer);
}

esp_err_t P256KeyPair::savePublicKeyB64(char *publicKey, size_t *publicKeyLen, bool isUrl)
{
    uint8_t buffer[P256_PUBLIC_KEY_SIZE];
    esp_err_t err;

    err = savePublicKey(buffer);
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

esp_err_t P256KeyPair::loadPrivateKeyB64(const char *privateKey, size_t privateKeyLen, bool isUrl)
{
    uint8_t buffer[P256_PRIVATE_KEY_SIZE];
    size_t decodedLen;
    esp_err_t err;

    decodedLen = sizeof(buffer);
    if (!fromB64(privateKey, privateKeyLen, isUrl, buffer, &decodedLen)) {
        ESP_LOGE(TAG, "Unable to decode base64 private key");
        return ESP_FAIL;
    }
    if (decodedLen == P256_PRIVATE_KEY_SIZE) {
        err = loadPrivateKey(buffer);
    }
    else {
        ESP_LOGE(TAG, "Invalid private key size: %d", decodedLen);
        err = ESP_ERR_INVALID_SIZE;
    }
    memset(buffer, 0, sizeof(buffer));
    return err;
}

esp_err_t P256KeyPair::savePrivateKeyB64(char *privateKey, size_t *privateKeyLen, bool isUrl)
{
    uint8_t buffer[P256_PRIVATE_KEY_SIZE];
    esp_err_t err;

    err = savePrivateKey(buffer);
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

bool P256KeyPair::validatePublicKey(const uint8_t *publicKey, size_t publicKeySize)
{
    uint8_t tempPk[P256_PUBLIC_KEY_SIZE];
    P256KeyPair pair;
    bool ret;

    if ((!publicKey) || publicKeySize != P256_PUBLIC_KEY_SIZE) {
        return false;
    }

    memcpy(tempPk, publicKey, P256_PUBLIC_KEY_SIZE);
    ret = !!(pair.loadPublicKey(tempPk) == ESP_OK);
    memset(tempPk, 0, sizeof(tempPk));

    // Done
    return ret;
}

void P256KeyPair::reset()
{
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);
}

// -----------------------------------------------------------------------------

esp_err_t ECDHKeyPair::generate()
{
    esp_err_t err;

    reset();
    // mbedtls_ecdh_gen_public is used despite its name because it will generate both
    // private and public keys in this scenario.
     err = mbedtls_ecdh_gen_public(&ecpGroup, &d, &q, mbedtls_ctr_drbg_random, &ctrDrbgCtx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to generate ECDH keys. Error: %d", err);
        return err;
    }

    // Done
    return ESP_OK;
}

esp_err_t ECDHKeyPair::computeSharedSecret(uint8_t sharedSecret[P256_SHARED_SECRET_SIZE])
{
    mbedtls_mpi temp;
    esp_err_t err;

    mbedtls_mpi_init(&temp);
    err = mbedtls_ecdh_compute_shared(&ecpGroup, &temp, &q, &d, mbedtls_ctr_drbg_random, &ctrDrbgCtx);
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

esp_err_t ECDSAKeyPair::generate()
{
    esp_err_t err;

    reset();
    err = mbedtls_ecp_gen_keypair(&ecpGroup, &d, &q, mbedtls_ctr_drbg_random, &ctrDrbgCtx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to generate ECDSA keys. Error: %d", err);
        return err;
    }

    // Done
    return ESP_OK;
}

esp_err_t ECDSAKeyPair::sign(const uint8_t hash[P256_HASH_SIZE], uint8_t signature[P256_SIGNATURE_SIZE])
{
    esp_err_t err;
    mbedtls_mpi r, s;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    err = mbedtls_ecdsa_sign(&ecpGroup, &r, &s, &d, hash, P256_HASH_SIZE, mbedtls_ctr_drbg_random, &ctrDrbgCtx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to sign hash. Error: %d", err);
        goto cleanup;
    }
    err = mbedtls_mpi_write_binary(&r, signature, 32);
    if (err == ESP_OK) {
        err = mbedtls_mpi_write_binary(&s, signature + 32, 32);
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

esp_err_t ECDSAKeyPair::verify(const uint8_t hash[P256_HASH_SIZE], const uint8_t signature[P256_SIGNATURE_SIZE])
{
    esp_err_t err;
    mbedtls_mpi r, s;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    err = mbedtls_mpi_read_binary(&r, signature, 32);
    if (err == ESP_OK) {
        err = mbedtls_mpi_read_binary(&s, signature + 32, 32);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to read signature. Error: %d", err);
        goto cleanup;
    }
    err = mbedtls_ecdsa_verify(&ecpGroup, hash, P256_HASH_SIZE, &q, &r, &s);
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
