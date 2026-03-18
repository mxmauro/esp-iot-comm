#pragma once

#include "sdkconfig.h"
#include "crypto/p256.h"
#include "mDNS/mDNS.h" // IWYU pragma: keep
#include "provisioning/wifi.h" // IWYU pragma: keep
#include <esp_err.h>
#include <stdint.h>
#include <string.h>

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

typedef esp_err_t (*IotCommGetDefaultRootUserPublicKeyCallback_t)(uint8_t publicKey[P256_PUBLIC_KEY_SIZE], void *ctx);

typedef esp_err_t (*IotCommLoadUsersFromStorageCallback_t)(void *dest, size_t destLen, void *ctx);
typedef esp_err_t (*IotCommSaveUsersToStorageCallback_t)(const void *data, size_t dataLen, void *ctx);

typedef struct IotCommClose_s {
    uint16_t reason;
    char     message[128];
} IotCommClose_t;

typedef struct IotCommEventSessionStart_s {
    uint32_t eventId;
    void     *handlerCtx;
    uint32_t sessionId;
    uint32_t userId;
    bool     userIsAdmin;
} IotCommEventSessionStart_t;

typedef struct IotCommEventSessionEnd_s {
    uint32_t eventId;
    void     *handlerCtx;
    uint32_t sessionId;
    uint32_t userId;
} IotCommEventSessionEnd_t;

typedef struct IotCommEventCustomCommand_s {
    uint32_t      eventId;
    void          *handlerCtx;
    uint32_t      sessionId;
    uint32_t      userId;
    bool          userIsAdmin;
    uint16_t      cmd;
    const uint8_t *data;
    size_t        dataLen;
} IotCommEventCustomCommand_t;


typedef struct IotCommUsersDefaultRootKeyProvider_s {
    IotCommGetDefaultRootUserPublicKeyCallback_t cb;
    void                                         *ctx;
} IotCommUsersDefaultRootKeyProvider_t;

typedef struct IotCommUsersStorageCallbacks_s {
    // NOTE: If load returns an error different from ESP_ERR_NOT_FOUND, it
    //       will be treated as a fatal error.
    IotCommLoadUsersFromStorageCallback_t load;
    IotCommSaveUsersToStorageCallback_t   save;
    void                                 *ctx;
} IotCommStorageCallbacks_t;

typedef struct IotCommRateLimitConfig_s {
    size_t   maxSlots;
    uint32_t windowSizeInMs;
    uint8_t  maxRequestsPerWindow;
    uint8_t  maxConsecutiveAuthFailures;
} IotCommRateLimitConfig_t;

typedef struct IotCommRateChallengeConfig_s {
    size_t   maxSlots;
    uint32_t windowSizeInMs;
} IotCommRateChallengeConfig_t;

typedef struct IotCommConfig_s {
    size_t                               maxUsersCount;
    IotCommUsersDefaultRootKeyProvider_t rootKey;
    IotCommStorageCallbacks_t            storage;
    IotCommRateLimitConfig_t             rateLimit;
    IotCommRateChallengeConfig_t         challenge;
    IotCommEventHandler_t                handler;
    void                                 *handlerCtx;
} IotCommConfig_t;

typedef struct IotCommServerConfig_s {
    uint16_t listenPort;
    uint16_t maxConnections;
    uint32_t maxPacketSize;
} IotCommServerConfig_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t iotCommInit(IotCommConfig_t *config);
void iotCommDeinit();

esp_err_t iotCommStartServer(IotCommServerConfig_t *config);
void iotCommStopServer();

bool iotCommIsServerRunning();

esp_err_t iotCommSetSessionUserData(uint32_t sessionId, void *ptr, IotCommUserDataFreeFunc_t freeFn);
void* iotCommGetSessionUserData(uint32_t sessionId);

// NOTE: Event replies are synchronous to the event callback. Do not retain event data
//       or defer completion to another task/core after the callback returns.
esp_err_t iotCommEventReply(uint32_t eventId, const uint8_t * reply, size_t replyLen);
esp_err_t iotCommEventReplyWithError(uint32_t eventId, uint32_t code, const char *message);

// NOTE: This function sends a standard websocket close except if called within a session start
//       event. In this case, reason and message will act as the HTTP(S) Upgrade request response.
// NOTE: Like iotCommEventReply*, this must be completed synchronously from the callback.
void iotCommSessionClose(uint32_t sessionId, uint16_t reason, const char *message);

static inline IotCommConfig_t iotCommDefaultConfig()
{
    IotCommConfig_t cfg;

    memset(&cfg, 0, sizeof(cfg));

    cfg.maxUsersCount = IOTCOMM_DEFAULT_MAX_USERS_COUNT;

    cfg.rateLimit.maxSlots = IOTCOMM_DEFAULT_MAX_RATE_LIMIT_SLOTS;
    cfg.rateLimit.windowSizeInMs = IOTCOMM_DEFAULT_RATE_LIMIT_WINDOW_TIME_MS;
    cfg.rateLimit.maxRequestsPerWindow = IOTCOMM_DEFAULT_MAX_RATE_LIMIT_REQUESTS_COUNT;
    cfg.rateLimit.maxConsecutiveAuthFailures = IOTCOMM_DEFAULT_MAX_RATE_LIMIT_CONSECUTIVE_FAILURES;

    cfg.challenge.maxSlots = IOTCOMM_DEFAULT_MAX_CHALLENGES_SLOTS;
    cfg.challenge.windowSizeInMs = IOTCOMM_DEFAULT_CHALLENGE_WINDOW_TIME_MS;

    return cfg;
}

static inline IotCommServerConfig_t iotCommDefaultServerConfig()
{
    IotCommServerConfig_t cfg;

    memset(&cfg, 0, sizeof(cfg));

    cfg.listenPort = 80;
    cfg.maxConnections = IOTCOMM_DEFAULT_MAX_USERS_COUNT + 2; // +2 for unauthenticated session

    return cfg;
}

// NOTE: Use this method only to initialize the root user key obtained, for example,
//       after device initialization with a captive portal.
esp_err_t iotCommInitRootUserPublicKey(const uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);

#ifdef __cplusplus
}
#endif // __cplusplus
