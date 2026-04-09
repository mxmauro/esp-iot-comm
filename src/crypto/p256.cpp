#include "iot_comm/crypto/p256.h"
#include "iot_comm/crypto/utils.h"
#include <assert.h>
#include <convert.h>
#include <esp_log.h>
#include <mutex.h>
#include <string.h>

#if ESP_IDF_VERSION_MAJOR >= 6
    #include <psa/crypto.h>
#else
    #include <mbedtls/ecdh.h>
    #include <mbedtls/ecdsa.h>
#endif

static const char* TAG = "P-256";

// -----------------------------------------------------------------------------

static Mutex initMtx;
static bool initialized = false;

#if ESP_IDF_VERSION_MAJOR < 6
static mbedtls_ecp_group ecpGroup = {};
#endif

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

#if ESP_IDF_VERSION_MAJOR >= 6
static psa_status_t importPrivateKey(psa_key_id_t *keyId, psa_algorithm_t alg, psa_key_usage_t usage, const P256KeyPair_t *pair);
static psa_status_t importPublicKey(psa_key_id_t *keyId, psa_algorithm_t alg, psa_key_usage_t usage, const P256KeyPair_t *pair);
#else
static int randomGen(void *ctx, unsigned char *dest, size_t count);
static esp_err_t loadPublicPoint(mbedtls_ecp_point *point, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);
static esp_err_t loadPrivateScalar(mbedtls_mpi *d, const uint8_t privateKey[P256_PRIVATE_KEY_SIZE]);
#endif

// -----------------------------------------------------------------------------

void p256KeyPairInit(P256KeyPair_t *pair)
{
    assert(pair);

    memset(pair, 0, sizeof(*pair));
}

void p256KeyPairDone(P256KeyPair_t *pair)
{
    assert(pair);

    memset(pair, 0, sizeof(*pair));
}

esp_err_t p256LoadPublicKey(P256KeyPair_t *pair, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE])
{
#if ESP_IDF_VERSION_MAJOR >= 6
    psa_key_id_t keyId = PSA_KEY_ID_NULL;
    psa_status_t status;
    P256KeyPair_t temp = {};
#else
    mbedtls_ecp_point q;
    esp_err_t err;
#endif

    assert(pair);

    DELAYED_P256_INIT();

#if ESP_IDF_VERSION_MAJOR >= 6
    memcpy(temp.publicKey, publicKey, P256_PUBLIC_KEY_SIZE);
    temp.hasPublicKey = true;

    status = importPublicKey(&keyId, PSA_ALG_ECDSA_ANY, PSA_KEY_USAGE_VERIFY_HASH, &temp);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Unable to load public key. Error: %d", status);
        return status;
    }
    psa_destroy_key(keyId);
#else
    mbedtls_ecp_point_init(&q);
    err = loadPublicPoint(&q, publicKey);
    mbedtls_ecp_point_free(&q);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to load public key. Error: %d", err);
        return err;
    }
#endif

    memcpy(pair->publicKey, publicKey, P256_PUBLIC_KEY_SIZE);
    pair->hasPublicKey = true;
    return ESP_OK;
}

esp_err_t p256SavePublicKey(P256KeyPair_t *pair, uint8_t publicKey[P256_PUBLIC_KEY_SIZE])
{
    assert(pair);

    DELAYED_P256_INIT();

    if (!pair->hasPublicKey) {
        ESP_LOGE(TAG, "No public key is loaded");
        return ESP_ERR_INVALID_STATE;
    }

    memcpy(publicKey, pair->publicKey, P256_PUBLIC_KEY_SIZE);
    return ESP_OK;
}

esp_err_t p256LoadPrivateKey(P256KeyPair_t *pair, const uint8_t privateKey[P256_PRIVATE_KEY_SIZE])
{
    assert(pair);

    DELAYED_P256_INIT();

    memcpy(pair->privateKey, privateKey, P256_PRIVATE_KEY_SIZE);
    pair->hasPrivateKey = true;
    return ESP_OK;
}

esp_err_t p256SavePrivateKey(P256KeyPair_t *pair, uint8_t privateKey[P256_PRIVATE_KEY_SIZE])
{
    assert(pair);

    DELAYED_P256_INIT();

    if (!pair->hasPrivateKey) {
        ESP_LOGE(TAG, "No private key is loaded");
        return ESP_ERR_INVALID_STATE;
    }

    memcpy(privateKey, pair->privateKey, P256_PRIVATE_KEY_SIZE);
    return ESP_OK;
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
#if ESP_IDF_VERSION_MAJOR >= 6
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t keyId = PSA_KEY_ID_NULL;
    size_t publicKeyLen = 0;
    size_t privateKeyLen = 0;
    psa_status_t status;
#else
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    size_t outLen = 0;
    esp_err_t err;
#endif

    assert(pair);

    DELAYED_P256_INIT();

#if ESP_IDF_VERSION_MAJOR >= 6
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

    status = psa_generate_key(&attr, &keyId);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Unable to generate ECDH keys. Error: %d", status);
        return status;
    }

    status = psa_export_public_key(keyId, pair->publicKey, sizeof(pair->publicKey), &publicKeyLen);
    if (status == PSA_SUCCESS) {
        status = psa_export_key(keyId, pair->privateKey, sizeof(pair->privateKey), &privateKeyLen);
    }
    psa_destroy_key(keyId);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Unable to export ECDH keys. Error: %d", status);
        memset(pair->privateKey, 0, sizeof(pair->privateKey));
        memset(pair->publicKey, 0, sizeof(pair->publicKey));
        pair->hasPrivateKey = false;
        pair->hasPublicKey = false;
        return status;
    }

    if ((publicKeyLen != P256_PUBLIC_KEY_SIZE) || (privateKeyLen != P256_PRIVATE_KEY_SIZE)) {
        ESP_LOGE(TAG, "Unexpected ECDH key sizes. Public: %d, Private: %d", publicKeyLen, privateKeyLen);
        memset(pair->privateKey, 0, sizeof(pair->privateKey));
        memset(pair->publicKey, 0, sizeof(pair->publicKey));
        pair->hasPrivateKey = false;
        pair->hasPublicKey = false;
        return ESP_FAIL;
    }

#else
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    // mbedtls_ecdh_gen_public is used despite its name because it will generate both
    // private and public keys in this scenario.
    err = mbedtls_ecdh_gen_public(&ecpGroup, &d, &q, randomGen, nullptr);
    if (err == ESP_OK) {
        err = mbedtls_mpi_write_binary(&d, pair->privateKey, P256_PRIVATE_KEY_SIZE);
        if (err == ESP_OK) {
            err = mbedtls_ecp_point_write_binary(&ecpGroup, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &outLen, pair->publicKey,
                                                 P256_PUBLIC_KEY_SIZE);
        }
        if ((err == ESP_OK) && (outLen != P256_PUBLIC_KEY_SIZE)) {
            err = ESP_FAIL;
        }
    }

    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to generate ECDH keys. Error: %d", err);
        memset(pair->privateKey, 0, sizeof(pair->privateKey));
        memset(pair->publicKey, 0, sizeof(pair->publicKey));
        pair->hasPrivateKey = false;
        pair->hasPublicKey = false;
        return err;
    }
#endif

    pair->hasPrivateKey = true;
    pair->hasPublicKey = true;
    return ESP_OK;
}

esp_err_t ecdhComputeSharedSecret(P256KeyPair_t *pair, uint8_t sharedSecret[P256_SHARED_SECRET_SIZE])
{
#if ESP_IDF_VERSION_MAJOR >= 6
    psa_key_id_t keyId = PSA_KEY_ID_NULL;
    size_t sharedSecretLen = 0;
    psa_status_t status;
#else
    mbedtls_mpi d;
    mbedtls_mpi temp;
    mbedtls_ecp_point q;
    esp_err_t err;
#endif

    assert(pair);

    DELAYED_P256_INIT();

    if (!pair->hasPrivateKey || !pair->hasPublicKey) {
        ESP_LOGE(TAG, "ECDH requires both a private key and a peer public key");
        return ESP_ERR_INVALID_STATE;
    }

#if ESP_IDF_VERSION_MAJOR >= 6
    status = importPrivateKey(&keyId, PSA_ALG_ECDH, PSA_KEY_USAGE_DERIVE, pair);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Unable to import ECDH private key. Error: %d", status);
        return status;
    }

    status = psa_raw_key_agreement(PSA_ALG_ECDH, keyId, pair->publicKey, P256_PUBLIC_KEY_SIZE, sharedSecret,
                                   P256_SHARED_SECRET_SIZE, &sharedSecretLen);
    psa_destroy_key(keyId);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Unable to compute shared secret. Error: %d", status);
        return status;
    }
    if (sharedSecretLen != P256_SHARED_SECRET_SIZE) {
        ESP_LOGE(TAG, "Unexpected shared secret size: %d", sharedSecretLen);
        return ESP_FAIL;
    }
#else
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&temp);
    mbedtls_ecp_point_init(&q);

    err = loadPrivateScalar(&d, pair->privateKey);
    if (err == ESP_OK) {
        err = loadPublicPoint(&q, pair->publicKey);
    }
    if (err == ESP_OK) {
        err = mbedtls_ecdh_compute_shared(&ecpGroup, &temp, &q, &d, randomGen, nullptr);
    }
    if (err == ESP_OK) {
        err = mbedtls_mpi_write_binary(&temp, sharedSecret, P256_SHARED_SECRET_SIZE);
    }

    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&temp);
    mbedtls_ecp_point_free(&q);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to compute shared secret. Error: %d", err);
        return err;
    }
#endif

    return ESP_OK;
}

// -----------------------------------------------------------------------------

esp_err_t ecdsaGeneratePair(P256KeyPair_t *pair)
{
#if ESP_IDF_VERSION_MAJOR >= 6
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t keyId = PSA_KEY_ID_NULL;
    size_t publicKeyLen = 0;
    size_t privateKeyLen = 0;
    psa_status_t status;
#else
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    size_t outLen = 0;
    esp_err_t err;
#endif

    assert(pair);

    DELAYED_P256_INIT();

#if ESP_IDF_VERSION_MAJOR >= 6
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA_ANY);

    status = psa_generate_key(&attr, &keyId);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Unable to generate ECDSA keys. Error: %d", status);
        return status;
    }

    status = psa_export_public_key(keyId, pair->publicKey, sizeof(pair->publicKey), &publicKeyLen);
    if (status == PSA_SUCCESS) {
        status = psa_export_key(keyId, pair->privateKey, sizeof(pair->privateKey), &privateKeyLen);
    }
    psa_destroy_key(keyId);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Unable to export ECDSA keys. Error: %d", status);
        memset(pair->privateKey, 0, sizeof(pair->privateKey));
        memset(pair->publicKey, 0, sizeof(pair->publicKey));
        pair->hasPrivateKey = false;
        pair->hasPublicKey = false;
        return status;
    }

    if ((publicKeyLen != P256_PUBLIC_KEY_SIZE) || (privateKeyLen != P256_PRIVATE_KEY_SIZE)) {
        ESP_LOGE(TAG, "Unexpected ECDSA key sizes. Public: %d, Private: %d", publicKeyLen, privateKeyLen);
        memset(pair->privateKey, 0, sizeof(pair->privateKey));
        memset(pair->publicKey, 0, sizeof(pair->publicKey));
        pair->hasPrivateKey = false;
        pair->hasPublicKey = false;
        return ESP_FAIL;
    }

#else
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    err = mbedtls_ecp_gen_keypair(&ecpGroup, &d, &q, randomGen, nullptr);
    if (err == ESP_OK) {
        err = mbedtls_mpi_write_binary(&d, pair->privateKey, P256_PRIVATE_KEY_SIZE);
        if (err == ESP_OK) {
            err = mbedtls_ecp_point_write_binary(&ecpGroup, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &outLen, pair->publicKey,
                                                 P256_PUBLIC_KEY_SIZE);
        }
        if ((err == ESP_OK) && (outLen != P256_PUBLIC_KEY_SIZE)) {
            err = ESP_FAIL;
        }
    }

    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to generate ECDSA keys. Error: %d", err);
        memset(pair->privateKey, 0, sizeof(pair->privateKey));
        memset(pair->publicKey, 0, sizeof(pair->publicKey));
        pair->hasPrivateKey = false;
        pair->hasPublicKey = false;
        return err;
    }
#endif

    pair->hasPrivateKey = true;
    pair->hasPublicKey = true;
    return ESP_OK;
}

esp_err_t ecdsaSign(P256KeyPair_t *pair, const uint8_t hash[P256_HASH_SIZE], uint8_t signature[P256_SIGNATURE_SIZE])
{
#if ESP_IDF_VERSION_MAJOR >= 6
    psa_key_id_t keyId = PSA_KEY_ID_NULL;
    size_t signatureLen = 0;
    psa_status_t status;
#else
    mbedtls_mpi d;
    mbedtls_mpi r;
    mbedtls_mpi s;
    esp_err_t err;
#endif

    assert(pair);

    DELAYED_P256_INIT();

    if (!pair->hasPrivateKey) {
        ESP_LOGE(TAG, "ECDSA signing requires a private key");
        return ESP_ERR_INVALID_STATE;
    }

#if ESP_IDF_VERSION_MAJOR >= 6
    status = importPrivateKey(&keyId, PSA_ALG_ECDSA_ANY, PSA_KEY_USAGE_SIGN_HASH, pair);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Unable to import ECDSA private key. Error: %d", status);
        return status;
    }

    status = psa_sign_hash(keyId, PSA_ALG_ECDSA_ANY, hash, P256_HASH_SIZE, signature, P256_SIGNATURE_SIZE, &signatureLen);
    psa_destroy_key(keyId);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Unable to sign hash. Error: %d", status);
        return status;
    }
    if (signatureLen != P256_SIGNATURE_SIZE) {
        ESP_LOGE(TAG, "Unexpected signature size: %d", signatureLen);
        return ESP_FAIL;
    }
#else
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    err = loadPrivateScalar(&d, pair->privateKey);
    if (err == ESP_OK) {
        err = mbedtls_ecdsa_sign(&ecpGroup, &r, &s, &d, hash, P256_HASH_SIZE, randomGen, nullptr);
    }
    if (err == ESP_OK) {
        err = mbedtls_mpi_write_binary(&r, signature, P256_SIGNATURE_SIZE / 2);
    }
    if (err == ESP_OK) {
        err = mbedtls_mpi_write_binary(&s, signature + P256_SIGNATURE_SIZE / 2, P256_SIGNATURE_SIZE / 2);
    }

    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to sign hash. Error: %d", err);
        return err;
    }
#endif

    return ESP_OK;
}

esp_err_t ecdsaVerify(P256KeyPair_t *pair, const uint8_t hash[P256_HASH_SIZE], const uint8_t signature[P256_SIGNATURE_SIZE])
{
#if ESP_IDF_VERSION_MAJOR >= 6
    psa_key_id_t keyId = PSA_KEY_ID_NULL;
    psa_status_t status;
#else
    mbedtls_ecp_point q;
    mbedtls_mpi r;
    mbedtls_mpi s;
    esp_err_t err;
#endif
    assert(pair);

    DELAYED_P256_INIT();

    if (!pair->hasPublicKey) {
        ESP_LOGE(TAG, "ECDSA verification requires a public key");
        return ESP_ERR_INVALID_STATE;
    }

#if ESP_IDF_VERSION_MAJOR >= 6
    status = importPublicKey(&keyId, PSA_ALG_ECDSA_ANY, PSA_KEY_USAGE_VERIFY_HASH, pair);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Unable to import ECDSA public key. Error: %d", status);
        return status;
    }

    status = psa_verify_hash(keyId, PSA_ALG_ECDSA_ANY, hash, P256_HASH_SIZE, signature, P256_SIGNATURE_SIZE);
    psa_destroy_key(keyId);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Signature verification failed. Error: %d", status);
        return status;
    }
#else
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    err = loadPublicPoint(&q, pair->publicKey);
    if (err == ESP_OK) {
        err = mbedtls_mpi_read_binary(&r, signature, P256_SIGNATURE_SIZE / 2);
    }
    if (err == ESP_OK) {
        err = mbedtls_mpi_read_binary(&s, signature + P256_SIGNATURE_SIZE / 2, P256_SIGNATURE_SIZE / 2);
    }
    if (err == ESP_OK) {
        err = mbedtls_ecdsa_verify(&ecpGroup, hash, P256_HASH_SIZE, &q, &r, &s);
    }

    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Signature verification failed. Error: %d", err);
        return err;
    }
#endif

    return ESP_OK;
}

// -----------------------------------------------------------------------------

static esp_err_t init()
{
    AutoMutex lock(initMtx);

    if (!initialized) {
#if ESP_IDF_VERSION_MAJOR >= 6
        psa_status_t status;
#else
        esp_err_t err;
#endif

#if ESP_IDF_VERSION_MAJOR >= 6
        status = psa_crypto_init();
        if (status != PSA_SUCCESS && status != PSA_ERROR_BAD_STATE) {
            ESP_LOGE(TAG, "Failed to initialize PSA Crypto. Error: %d", status);
            return status;
        }
#else
        mbedtls_ecp_group_init(&ecpGroup);
        err = mbedtls_ecp_group_load(&ecpGroup, MBEDTLS_ECP_DP_SECP256R1);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to load ECP group. Error: %d", err);
            mbedtls_ecp_group_free(&ecpGroup);
            return err;
        }
#endif

        initialized = true;
    }

    return ESP_OK;
}

#if ESP_IDF_VERSION_MAJOR >= 6
static psa_status_t importPrivateKey(psa_key_id_t *keyId, psa_algorithm_t alg, psa_key_usage_t usage, const P256KeyPair_t *pair)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_algorithm(&attr, alg);

    status = psa_import_key(&attr, pair->privateKey, P256_PRIVATE_KEY_SIZE, keyId);
    psa_reset_key_attributes(&attr);
    return status;
}

static psa_status_t importPublicKey(psa_key_id_t *keyId, psa_algorithm_t alg, psa_key_usage_t usage, const P256KeyPair_t *pair)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_algorithm(&attr, alg);

    status = psa_import_key(&attr, pair->publicKey, P256_PUBLIC_KEY_SIZE, keyId);
    psa_reset_key_attributes(&attr);
    return status;
}
#else
static int randomGen(void *ctx, unsigned char *dest, size_t count)
{
    (void)ctx;
    return (int)randomize((uint8_t *)dest, count);
}

static esp_err_t loadPublicPoint(mbedtls_ecp_point *point, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE])
{
    mbedtls_ecp_point_free(point);
    mbedtls_ecp_point_init(point);
    return mbedtls_ecp_point_read_binary(&ecpGroup, point, publicKey, P256_PUBLIC_KEY_SIZE);
}

static esp_err_t loadPrivateScalar(mbedtls_mpi *d, const uint8_t privateKey[P256_PRIVATE_KEY_SIZE])
{
    mbedtls_mpi_free(d);
    mbedtls_mpi_init(d);
    return mbedtls_mpi_read_binary(d, privateKey, P256_PRIVATE_KEY_SIZE);
}
#endif
