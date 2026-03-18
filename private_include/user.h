#pragma once

#include "iot_comm/crypto/p256.h"
#include <esp_err.h>

// -----------------------------------------------------------------------------

typedef esp_err_t (*GetDefaultRootUserPublicKeyCallback_t)(uint8_t publicKey[P256_PUBLIC_KEY_SIZE], void *ctx);

typedef esp_err_t (*LoadUsersFromStorageCallback_t)(void *dest, size_t destLen, void *ctx);
typedef esp_err_t (*SaveUsersToStorageCallback_t)(const void *data, size_t dataLen, void *ctx);

typedef struct UsersDefaultRootKeyProvider_s {
    GetDefaultRootUserPublicKeyCallback_t cb;
    void                                  *ctx;
} UsersDefaultRootKeyProvider_t;

typedef struct UsersStorageCallbacks_s {
    // NOTE: If load returns an error different from ESP_ERR_NOT_FOUND, it
    //       will be treated as a fatal error.
    LoadUsersFromStorageCallback_t load;
    SaveUsersToStorageCallback_t   save;
    void                           *ctx;
} UsersStorageCallbacks_t;

typedef struct UsersConfig_s {
    size_t                        maxUsersCount;
    UsersDefaultRootKeyProvider_t rootKey;
    UsersStorageCallbacks_t       storage;
} UsersConfig_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t usersInit(UsersConfig_t *config);
void usersDeinit();

// Returns user id on success, else 0.
uint32_t userCreate(const char *name, size_t nameLen, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);
esp_err_t userDestroy(uint32_t userId);

uint32_t userGetID(const char *name, size_t nameLen);

esp_err_t userChangeCredentials(uint32_t userId, uint32_t requestingUserId, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);

esp_err_t userVerifySignature(uint32_t userId, const uint8_t hash[P256_HASH_SIZE], const uint8_t signature[P256_SIGNATURE_SIZE]);

esp_err_t userMustChangeCredentials(uint32_t userId, bool *mustChange);
esp_err_t userIsAdmin(uint32_t userId, bool *isAdmin);

#ifdef __cplusplus
}
#endif // __cplusplus
