#pragma once

#include "sdkconfig.h"
#include "crypto/p256.h"
#include "mDNS\mDNS.h" // IWYU pragma: keep
#include "provisioning\wifi.h" // IWYU pragma: keep
#include <esp_err.h>
#include <simple_function_ref.h>
#include <stdint.h>
#include <storage/istorage.h>

#if (!defined(CONFIG_HTTPD_WS_SUPPORT))
    #error This library requires CONFIG_HTTPD_WS_SUPPORT to be enabled
#endif

#if (!defined(CONFIG_ESP_SYSTEM_EVENT_TASK_STACK_SIZE)) || CONFIG_ESP_SYSTEM_EVENT_TASK_STACK_SIZE < 4096
    #error This library requires CONFIG_ESP_SYSTEM_EVENT_TASK_STACK_SIZE to have a minimum value of 4096
#endif

#define IOTCOMM_DEFAULT_MAX_USERS_COUNT                     4
#define IOTCOMM_DEFAULT_MAX_RATE_LIMIT_SLOTS                20
#define IOTCOMM_DEFAULT_RATE_LIMIT_WINDOW_TIME_MS           60000
#define IOTCOMM_DEFAULT_MAX_RATE_LIMIT_REQUESTS_COUNT       3
#define IOTCOMM_DEFAULT_MAX_RATE_LIMIT_CONSECUTIVE_FAILURES 3
#define IOTCOMM_DEFAULT_MAX_CHALLENGES_SLOTS                10
#define IOTCOMM_DEFAULT_CHALLENGE_WINDOW_TIME_MS            60000

// CMD_CREATE_USER (0x7FF1)
//           name: NUL-terminated string
//     public key: raw 65-byte uncompressed ECDSA public key
//
// CMD_DELETE_USER (0x7FF2)
//     name: NUL-terminated string
//
// CMD_RESET_USER_CREDENTIALS (0x7FF3)
//               name: NUL-terminated string
//     new public key: raw 65-byte uncompressed ECDSA public key
//
// CMD_CHANGE_USER_CREDENTIALS (0x7FF4)
//     new public key: raw 65-byte uncompressed ECDSA public key
//
// CMD_SET_HOSTNAME (0x7FF5)
//     key id: 1-byte value of id.
//        key: 16-byte pre-shared key blob.
//

// Websocket close codes
#define WS_CLOSE_NORMAL                           1000  // Normal closure; connection completed successfully
#define WS_CLOSE_GOING_AWAY                       1001  // Endpoint is going away (server shutdown or browser nav)
#define WS_CLOSE_PROTOCOL_ERROR                   1002  // Protocol error (e.g., invalid frame)
#define WS_CLOSE_UNSUPPORTED_DATA                 1003  // Unsupported data type
#define WS_CLOSE_NO_STATUS                        1005  // No status code present (MUST NOT be set in a close frame)
#define WS_CLOSE_ABNORMAL                         1006  // Abnormal closure (MUST NOT be set in a close frame)
#define WS_CLOSE_INVALID_PAYLOAD                  1007  // Invalid payload data (e.g., bad UTF-8)
#define WS_CLOSE_POLICY_VIOLATION                 1008  // Policy violation (generic)
#define WS_CLOSE_MESSAGE_TOO_BIG                  1009  // Message too big to process
#define WS_CLOSE_MANDATORY_EXT                    1010  // Missing required extension
#define WS_CLOSE_INTERNAL_ERROR                   1011  // Internal server error
#define WS_CLOSE_TLS_HANDSHAKE_FAIL               1015  // TLS handshake failure (MUST NOT be set in a close frame)

// Application-defined websocket close codes
#define WS_CLOSE_APP_SESSION_NOT_FOUND            4001
#define WS_CLOSE_APP_CREDENTIALS_CHANGE_MANDATORY 4002

// -----------------------------------------------------------------------------

typedef enum IotCommEvent_e {
    IotCommEventSessionStart = 1,
    IotCommEventSessionEnd,
    IotCommEventCustomCommand
} IotCommEvent_t;

typedef void (*IotCommEventHandler_t)(IotCommEvent_t event, void *eventData);

typedef void (*IotCommUserDataFreeFunc_t)(void *userData);

typedef struct IotCommClose_s {
    uint16_t reason;
    char     message[128];
} IotCommClose_t;

typedef struct IotCommEventSessionStart_s {
    uint32_t sessionId;
    uint32_t userId;
    bool     userIsAdmin;

    SimpleFunctionRef<void, esp_err_t /*err*/> setError;

    // Sets a per-session custom data pointer and a cleanup routine.
    SimpleFunctionRef<void, const void * /*ptr*/, IotCommUserDataFreeFunc_t /*freeFn*/> setUserData;
} IotCommEventSessionStart_t;

typedef struct IotCommEventSessionEnd_s {
    uint32_t sessionId;
    uint32_t userId;

    SimpleFunctionRef<void *> getUserData;
} IotCommEventSessionEnd_t;

typedef struct IotCommEventCustomCommand_s {
    uint32_t      sessionId;
    uint32_t      userId;
    bool          userIsAdmin;
    uint16_t      cmd;
    const uint8_t *data;
    size_t        dataLen;

    SimpleFunctionRef<void *> getUserData;

    SimpleFunctionRef<bool, const uint8_t * /*reply*/, size_t /*replyLen*/> reply;
    SimpleFunctionRef<bool, uint32_t /*code*/, const char * /*message*/> replyWithError;
    SimpleFunctionRef<void, uint16_t /*reason*/, const char * /*message*/> close;
} IotCommEventCustomCommand_t;

typedef esp_err_t (*IotCommGetDefaultRootPublicKey_t)(uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);

typedef struct IotCommConfig_s {
    uint16_t listenPort;
    uint16_t maxConnections;

    size_t                           maxUsersCount;
    IStorage                         *usersStorage;
    IotCommGetDefaultRootPublicKey_t fnGetDefRootUserPublicKey;

    size_t   maxRateLimitSlots;
    uint32_t rateLimitWindowSizeInMs;
    uint8_t  maxRequestsPerWindow;
    uint8_t  maxConsecutiveAuthFailures;

    size_t maxChallengesSlot;
    uint32_t challengeWindowSizeInMs;

    IotCommEventHandler_t handler;
} IotCommConfig_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t iotCommInit(IotCommConfig_t *config);
void iotCommDone();

bool iotCommIsRunning();

static inline IotCommConfig_t iotCommDefaultConfig()
{
    IotCommConfig_t cfg;

    memset(&cfg, 0, sizeof(cfg));

    cfg.listenPort = 80;
    cfg.maxConnections = IOTCOMM_DEFAULT_MAX_USERS_COUNT + 2; // +2 for unauthenticated session

    cfg.maxUsersCount = IOTCOMM_DEFAULT_MAX_USERS_COUNT;

    cfg.maxRateLimitSlots = IOTCOMM_DEFAULT_MAX_RATE_LIMIT_SLOTS;
    cfg.rateLimitWindowSizeInMs = IOTCOMM_DEFAULT_RATE_LIMIT_WINDOW_TIME_MS;
    cfg.maxRequestsPerWindow = IOTCOMM_DEFAULT_MAX_RATE_LIMIT_REQUESTS_COUNT;
    cfg.maxConsecutiveAuthFailures = IOTCOMM_DEFAULT_MAX_RATE_LIMIT_CONSECUTIVE_FAILURES;

    cfg.maxChallengesSlot = IOTCOMM_DEFAULT_MAX_CHALLENGES_SLOTS;
    cfg.challengeWindowSizeInMs = IOTCOMM_DEFAULT_CHALLENGE_WINDOW_TIME_MS;

    return cfg;
}

#ifdef __cplusplus
}
#endif // __cplusplus
