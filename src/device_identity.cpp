#include "device_identity.h"
#include <esp_log.h>
#include <string.h>

static const char* TAG = "DeviceIdentity";

// -----------------------------------------------------------------------------

typedef struct DeviceIdentityStorageBlob_s {
    uint8_t privateKey[P256_PRIVATE_KEY_SIZE];
    uint8_t publicKey[P256_PUBLIC_KEY_SIZE];
} DeviceIdentityStorageBlob_t;

// -----------------------------------------------------------------------------

static P256KeyPair_t deviceIdentity = {};

// -----------------------------------------------------------------------------

static esp_err_t validateDeviceIdentity(uint8_t hashValue);

// -----------------------------------------------------------------------------

esp_err_t deviceIdentityInit(const IotCommStorageCallbacks_t *storage)
{
    DeviceIdentityStorageBlob_t blob;
    esp_err_t err;

    if ((!storage) || (!storage->load) || (!storage->save)) {
        return ESP_ERR_INVALID_ARG;
    }

    deviceIdentityDeinit();

    // Load device identity
    memset(&blob, 0, sizeof(blob));
    err = storage->load(IotCommStorageItemTypeDeviceIdentityKeyPair, &blob, sizeof(blob), storage->ctx);
    if (err == ESP_ERR_NOT_FOUND) {
        err = ecdsaGeneratePair(&deviceIdentity);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to generate the device identity key pair. Error: %d.", err);
            goto done;
        }

        err = validateDeviceIdentity(0xA5);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Generated device identity validation failed. Error: %d.", err);
            goto done;
        }

        // Save device identidy
        err = p256SavePrivateKey(&deviceIdentity, blob.privateKey);
        if (err == ESP_OK) {
            err = p256SavePublicKey(&deviceIdentity, blob.publicKey);
        }
        if (err != ESP_OK) {
            goto done;
        }

        err = storage->save(IotCommStorageItemTypeDeviceIdentityKeyPair, &blob, sizeof(blob), storage->ctx);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to save the device identity to storage. Error: %d.", err);
            goto done;
        }

    }
    else if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to load the device identity from storage. Error: %d.", err);
        goto done;
    }
    else {
        err = p256LoadPrivateKey(&deviceIdentity, blob.privateKey);
        if (err == ESP_OK) {
            err = p256LoadPublicKey(&deviceIdentity, blob.publicKey);
        }
        if (err == ESP_OK) {
            err = validateDeviceIdentity(0x3C);
        }
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Stored device identity validation failed. Error: %d.", err);
            goto done;
        }
    }

    err = ESP_OK;

done:
    memset(&blob, 0, sizeof(blob));
    if (err != ESP_OK) {
        deviceIdentityDeinit();
    }
    return err;
}

void deviceIdentityDeinit()
{
    p256KeyPairDone(&deviceIdentity);
}

esp_err_t deviceIdentityGetPublicKey(uint8_t publicKey[P256_PUBLIC_KEY_SIZE])
{
    if (!deviceIdentity.hasPublicKey) {
        return ESP_ERR_INVALID_STATE;
    }
    return p256SavePublicKey(&deviceIdentity, publicKey);
}

esp_err_t deviceIdentitySignHash(const uint8_t hash[P256_HASH_SIZE], uint8_t signature[P256_SIGNATURE_SIZE])
{
    if (!deviceIdentity.hasPrivateKey) {
        return ESP_ERR_INVALID_STATE;
    }
    return ecdsaSign(&deviceIdentity, hash, signature);
}

// -----------------------------------------------------------------------------

static esp_err_t validateDeviceIdentity(uint8_t hashValue)
{
    uint8_t hash[P256_HASH_SIZE];
    uint8_t signature[P256_SIGNATURE_SIZE];
    esp_err_t err;

    memset(hash, hashValue, sizeof(hash));
    err = ecdsaSign(&deviceIdentity, hash, signature);
    if (err == ESP_OK) {
        err = ecdsaVerify(&deviceIdentity, hash, signature);
    }

    memset(hash, 0, sizeof(hash));
    memset(signature, 0, sizeof(signature));
    return err;
}
