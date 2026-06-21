#pragma once

#include "iot_comm/iot_comm.h"
#include "iot_comm/crypto/p256.h"
#include <esp_err.h>

// -----------------------------------------------------------------------------

typedef struct UsersConfig_s {
    size_t                               maxUsersCount;
    IotCommUsersDefaultRootKeyProvider_t rootKey;
    IotCommStorageCallbacks_t            storage;
} UsersConfig_t;

// -----------------------------------------------------------------------------

#define USER_CREATE_FLAG_MUST_CHANGE_CREDENTIALS_ON_NEXT_LOGIN 0x01

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t usersInit(UsersConfig_t *config);
void usersDeinit();

// Returns user id on success, else 0.
uint32_t userCreate(uint8_t flags, const char *name, size_t nameLen, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);
esp_err_t userDestroy(uint32_t userId);

uint32_t userGetID(const char *name, size_t nameLen);

esp_err_t userChangeCredentials(uint32_t userId, uint32_t requestingUserId, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);

esp_err_t userVerifySignature(uint32_t userId, const uint8_t hash[P256_HASH_SIZE], const uint8_t signature[P256_SIGNATURE_SIZE]);

esp_err_t userMustChangeCredentials(uint32_t userId, bool *mustChange);
esp_err_t userIsAdmin(uint32_t userId, bool *isAdmin);

#ifdef __cplusplus
}
#endif // __cplusplus
