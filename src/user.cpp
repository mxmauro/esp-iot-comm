#include "user.h"
#include <esp_log.h>
#include <esp_random.h>
#include <fnv.h>
#include <freertos/FreeRTOS.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <string.h>
#include <time.h>

static const char* TAG = "Users";

#define ADMIN_USER_INDEX 0

#define X_ESP_ERR_CANCELLED -1000

// -----------------------------------------------------------------------------

typedef struct User_s {
    uint32_t id; // ID MUST be the first member
    char     name[32];
    uint8_t  publicKey[P256_PUBLIC_KEY_SIZE];
    uint8_t  inUse                    : 1;
    uint8_t  mustChangeCredentials    : 1;
    uint8_t  lastCredentialsChangeMin : 6;
} User_t;

// -----------------------------------------------------------------------------

static const char *stgUsersKey = "usersMgr";

static IStorage *storage = nullptr;
static User_t *users = nullptr; // User 0 is the administrator
static size_t maxUsersCount = 0;

// -----------------------------------------------------------------------------

static esp_err_t saveAllUsers();
static User_t* findUserByName(const char *name, size_t nameLen);
static User_t* findUserByID(uint32_t id);
static void internalCreateUser(User_t *user, const char *name, size_t nameLen, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);
static esp_err_t internalChangeUserCredentials(User_t *user, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE], bool force, bool isReset);
static size_t getUserNameLength(const User_t *user);
static uint8_t getMinuteMod64();

static bool validateUserName(const char *name, size_t nameLen);

// -----------------------------------------------------------------------------

esp_err_t usersInit(size_t _maxUsersCount, IStorage *_storage, UsersGetDefaultRootPublicKey_t fnGetDefRootPublicKey)
{
    StorageBlob_t data;
    esp_err_t err;

    assert(_maxUsersCount < (size_t)-1);
    assert(_storage);
    assert(fnGetDefRootPublicKey);

    users = (User_t *)malloc((1 + _maxUsersCount) * sizeof(User_t));
    if (!users) {
        ESP_LOGE(TAG, "Unable to allocate memory for users.");
        return ESP_ERR_NO_MEM;
    }

    maxUsersCount = _maxUsersCount;
    storage = _storage;

    err = _storage->readBlob(stgUsersKey, data);
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
        ESP_LOGE(TAG, "Unable to read users from flash memory. Error: %d.", err);
        usersDone();
        return err;
    }

    if (err == ESP_OK && data.len == (1 + maxUsersCount) * sizeof(User_t)) {
        memcpy(users, data.value.get(), data.len);
    }
    else {
        uint8_t tempPublicKey[P256_PUBLIC_KEY_SIZE];

        // Load defaults
        memset(users, 0, (1 + maxUsersCount) * sizeof(User_t));

        // Get the default root public key from callback
        err = fnGetDefRootPublicKey(tempPublicKey);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Unable to create the default administrator user. Error: %d.", err);
            usersDone();
            return err;
        }

        // Create root user
        internalCreateUser(&users[0], "root", 4, tempPublicKey);

        memset(tempPublicKey, 0, sizeof(tempPublicKey));

        // Save users
        err = saveAllUsers();
        if (err != ESP_OK) {
            usersDone();
            return err;
        }
    }

    // Done
    return ESP_OK;
}

void usersDone()
{
    if (users) {
        memset(users, 0, (1 + maxUsersCount) * sizeof(User_t));
        free(users);
        users = nullptr;
    }
    storage = nullptr;
    maxUsersCount = 0;
}

uint32_t userCreate(const char *name, size_t nameLen, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE])
{
    User_t *user;
    esp_err_t err;

    if (!validateUserName(name, nameLen)) {
        ESP_LOGE(TAG, "Invalid parameters for create user.");
        return 0;
    }

    user = findUserByName(name, nameLen);
    if (user) {
        ESP_LOGE(TAG, "User already exists.");
        return 0;
    }

    for (int i = 1; i < 1 + maxUsersCount; i++) {
        if (!users[i].inUse) {
            user = users + i;
            break;
        }
    }
    if (!user) {
        ESP_LOGE(TAG, "Reached the maximum number of users.");
        return 0;
    }

    // Add new user
    internalCreateUser(user, name, nameLen, publicKey);

    // Save users
    err = saveAllUsers();
    if (err != ESP_OK) {
        memset(user, 0, sizeof(User_t));
        return 0;
    }

    // Done
    ESP_LOGI(TAG, "User '%.*s' successfully created with ID #%u.", (int)nameLen, name, user->id);
    return user->id;
}

esp_err_t userDestroy(uint32_t userId)
{
    User_t oldUser;
    User_t *user;
    esp_err_t err;

    user = findUserByID(userId);
    if ((!user) || user == &users[0]) {
        ESP_LOGE(TAG, "User not found.");
        return ESP_ERR_NOT_FOUND;
    }
    // Make a copy of the original user data for logging and recovery if needed
    memcpy(&oldUser, user, sizeof(User_t));

    // Delete user
    memset(user, 0, sizeof(User_t));

    // Save users
    err = saveAllUsers();
    if (err != ESP_OK) {
        memcpy(user, &oldUser, sizeof(User_t));
        memset(&oldUser, 0, sizeof(User_t));
        return err;
    }

    // Done
    ESP_LOGI(TAG, "User '%.*s' with ID #%u was successfully deleted.", (int)getUserNameLength(&oldUser), oldUser.name, oldUser.id);
    memset(&oldUser, 0, sizeof(User_t));
    return ESP_OK;
}

uint32_t userGetID(const char *name, size_t nameLen)
{
    User_t *user = findUserByName(name, nameLen);

    // Done
    return user ? user->id : 0;
}

esp_err_t userChangeCredentials(uint32_t userId, uint32_t requestingUserId, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE])
{
    ECDSAKeyPair keyPair;
    User_t *user;
    User_t origUser;
    bool forceAndReset;
    esp_err_t err;

    user = findUserByID(userId);
    if (!user) {
        ESP_LOGE(TAG, "User not found.");
        return ESP_ERR_NOT_FOUND;
    }

    // Change user credentials
    if (requestingUserId == userId) {
        // Normal user request (or admin changing own credentials)
        forceAndReset = false;
    }
    else if (requestingUserId == users[0].id) {
        // Admin request
        forceAndReset = true;
    } else {
        ESP_LOGE(TAG, "Only admin users can change other users' credentials.");
        memset(&origUser, 0, sizeof(User_t));
        return ESP_ERR_INVALID_STATE;
    }

    // Try to load the public key to check if valid
    err = keyPair.loadPublicKey(publicKey);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to load new credentials. Error: %d.", err);
        return err;
    }

    // Make a copy of the original user data
    memcpy(&origUser, user, sizeof(User_t));

    // Update credentials
    err = internalChangeUserCredentials(user, publicKey, forceAndReset, forceAndReset);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to change user credentials.");
        memcpy(user, &origUser, sizeof(User_t));
        memset(&origUser, 0, sizeof(User_t));
        return err;
    }

    // Save users
    err = saveAllUsers();
    if (err != ESP_OK) {
        memcpy(user, &origUser, sizeof(User_t));
        memset(&origUser, 0, sizeof(User_t));
        return err;
    }

    // Done
    ESP_LOGI(TAG, "Credentials successfully changed.");
    memset(&origUser, 0, sizeof(User_t));
    return ESP_OK;
}

esp_err_t userVerifySignature(uint32_t userId, const uint8_t hash[P256_HASH_SIZE],
                              const uint8_t signature[P256_SIGNATURE_SIZE])
{
    ECDSAKeyPair keyPair;
    User_t *user;
    esp_err_t err;

    user = findUserByID(userId);
    if (!user) {
        ESP_LOGE(TAG, "User not found or credentials mismatch.");
        return ESP_ERR_NOT_FOUND;
    }

    err = keyPair.loadPublicKey(user->publicKey);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to load user credentials. Error: %d.", err);
        return err;
    }
    err = keyPair.verify(hash, signature);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Signature verification failed. Error: %d.", err);
        return err;
    }

    // Done
    return ESP_OK;
}

esp_err_t userMustChangeCredentials(uint32_t userId, bool *mustChange)
{
    User_t *user;

    assert(mustChange);
    *mustChange = false;

    user = findUserByID(userId);
    if (!user) {
        return ESP_ERR_NOT_FOUND;
    }

    // Done
    *mustChange = user->mustChangeCredentials;
    return ESP_OK;
}

esp_err_t userIsAdmin(uint32_t userId, bool *isAdmin)
{
    User_t *user;

    assert(isAdmin);
    *isAdmin = false;

    user = findUserByID(userId);
    if (!user) {
        return ESP_ERR_NOT_FOUND;
    }

    // Done
    *isAdmin = !!(user == &users[0]);
    return ESP_OK;
}

// -----------------------------------------------------------------------------

static esp_err_t saveAllUsers()
{
    esp_err_t err;

    err = storage->writeBlob(stgUsersKey, users, (1 + maxUsersCount) * sizeof(User_t));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to save users into storage. Error: %d.", err);
    }
    return err;
}

static User_t* findUserByName(const char *name, size_t nameLen)
{
    if ((!name) || nameLen < 1 || nameLen > sizeof(users[0].name)) {
        return nullptr;
    }
    for (size_t i = 0; i < 1 + maxUsersCount; i++) {
        if (users[i].inUse && memcmp(users[i].name, name, nameLen) == 0 &&
            (nameLen == sizeof(users[0].name) || users[i].name[nameLen] == 0)
        ) {
            return users + i;
        }
    }
    return nullptr;
}

static User_t* findUserByID(uint32_t id)
{
    for (size_t i = 0; i < 1 + maxUsersCount; i++) {
        if (users[i].inUse && users[i].id == id) {
            return users + i;
        }
    }
    return nullptr;
}

static void internalCreateUser(User_t *user, const char *name, size_t nameLen, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE])
{
    uint64_t ui64;
    uint32_t ui32;

    memset(user, 0, sizeof(User_t));
    memcpy(user->name, name, nameLen);
    memcpy(user->publicKey, publicKey, P256_PUBLIC_KEY_SIZE);
    user->inUse = 1;
    user->mustChangeCredentials = 1;

    ui32 = esp_random();
    ui64 = now_ms();

    user->id = fnv1a32(user->name, sizeof(user->name));
    user->id = fnv1a32(user->publicKey, sizeof(user->publicKey), user->id);
    user->id = fnv1a32(&ui32, sizeof(ui32), user->id);
    user->id = fnv1a32(&ui64, sizeof(ui64), user->id);
    user->id = fnv1a32(&name, sizeof(char *));
    if (user->id == 0) {
        user->id = 1;
    }
}

static esp_err_t internalChangeUserCredentials(User_t *user, const uint8_t publicKey[P256_PUBLIC_KEY_SIZE], bool force, bool isReset)
{
    uint8_t minMod64 = getMinuteMod64();

    if (!force) {
        // If the credentials are being changed in the same "minute"
        // NOTE: 6 bits are used so every 64 minutes it exists the possibility of a wrong check
        if (user->lastCredentialsChangeMin == minMod64) {
            // If we are changing, disallow both double change and reset/change
            return X_ESP_ERR_CANCELLED;
        }
    }

    memcpy(user->publicKey, publicKey, P256_PUBLIC_KEY_SIZE);
    user->mustChangeCredentials = (isReset) ? 1 : 0;
    user->lastCredentialsChangeMin = minMod64 == 0 ? 0x3F : (minMod64 - 1);

    // Done
    return ESP_OK;
}

static size_t getUserNameLength(const User_t *user)
{
    size_t nameLen;

    for (nameLen = 0; nameLen < sizeof(user->name) && user->name[nameLen] != 0; nameLen++);
    return nameLen;
}

static uint8_t getMinuteMod64()
{
    return (uint8_t)(now_ms() / (60 * 1000)) & 0x3F;
}

static bool validateUserName(const char *name, size_t nameLen)
{
    size_t i;

    if ((!name) || nameLen < 1 || nameLen > sizeof(users[0].name)) {
        return false;
    }
    for (i = 0; i < nameLen; i++) {
        if ((name[i] < '0' || name[i] > '9') &&
            (name[i] < 'A' || name[i] > 'Z') &&
            (name[i] < 'a' || name[i] > 'z')
        ) {
            if (name[i] != '_' && name[i] != '-') {
                return false;
            }
            if (i == 0 || i == nameLen - 1) {
                return false;
            }
        }
    }
    return true;
}
