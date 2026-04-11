#pragma once

#include "sdkconfig.h"
#include "crypto/p256.h"
#include "provisioning/wifi.h" // IWYU pragma: keep
#include "utils/network.h"
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

// The following commands are handled by the IoT-Comm engine.
//
// NOTE: Command in the 0x7F00-0x7FFF range are reserved for current and future use.
//
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
// CMD_OTA_BEGIN (0x7FF5)
//     image size: 4-byte big-endian image size in bytes
//
// CMD_OTA_WRITE (0x7FF6)
//     chunk: remaining packet payload bytes
//
// CMD_OTA_CANCEL (0x7FF7)
//     no payload
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

// Identifies the kind of event delivered to the application callback.
typedef enum IotCommEventType_e {
    IotCommEventTypeSessionStart = 1,
    IotCommEventTypeSessionEnd,
    IotCommEventTypeCustomCommand
} IotCommEventType_t;

// Releases per-session user data when the library no longer needs it.
typedef void (*IotCommUserDataFreeFunc_t)(void *userData);

// Provides the initial root user public key when no stored users are available.
typedef esp_err_t (*IotCommGetDefaultRootUserPublicKeyCallback_t)(uint8_t publicKey[P256_PUBLIC_KEY_SIZE], void *ctx);

// Loads the serialized user database from persistent storage.
typedef esp_err_t (*IotCommLoadUsersFromStorageCallback_t)(void *dest, size_t destLen, void *ctx);
// Saves the serialized user database to persistent storage.
typedef esp_err_t (*IotCommSaveUsersToStorageCallback_t)(const void *data, size_t dataLen, void *ctx);

// Opaque handle used to identify an active client session.
typedef void* IotCommSessionHandle_t;

// Carries the payload associated with a custom command event.
typedef struct IotCommCustomCommandEvent_s {
    uint16_t      cmd;
    const uint8_t *data;
    size_t        dataLen;
} IotCommCustomCommandEvent_t;

// Describes an event emitted by the IoT communication server.
typedef struct IotCommEvent_s {
    IotCommEventType_t     eventType;
    IotCommSessionHandle_t sessionHandle;
    void                   *ctx;
    union {
        IotCommCustomCommandEvent_t *command;
    };
} IotCommEvent_t;

// Groups the callback used to obtain the default root user key.
typedef struct IotCommUsersDefaultRootKeyProvider_s {
    IotCommGetDefaultRootUserPublicKeyCallback_t cb;
    void                                         *ctx;
} IotCommUsersDefaultRootKeyProvider_t;

// Collects the callbacks used to persist and restore users.
typedef struct IotCommUsersStorageCallbacks_s {
    // NOTE: If load returns an error different from ESP_ERR_NOT_FOUND, it
    //       will be treated as a fatal error.
    IotCommLoadUsersFromStorageCallback_t load;
    IotCommSaveUsersToStorageCallback_t   save;
    void                                 *ctx;
} IotCommStorageCallbacks_t;

// Configures request throttling for authentication and command traffic.
typedef struct IotCommRateLimitConfig_s {
    size_t   maxSlots;
    uint32_t windowSizeInMs;
    uint8_t  maxRequestsPerWindow;
    uint8_t  maxConsecutiveAuthFailures;
} IotCommRateLimitConfig_t;

// Configures rate limiting for challenge generation.
typedef struct IotCommRateChallengeConfig_s {
    size_t   maxSlots;
    uint32_t windowSizeInMs;
} IotCommRateChallengeConfig_t;

// Receives server lifecycle and command events.
typedef void (*IotCommEventHandler_t)(IotCommEvent_t *event);

// Holds the runtime configuration for the IoT communication subsystem.
typedef struct IotCommConfig_s {
    size_t                               maxUsersCount;
    IotCommUsersDefaultRootKeyProvider_t rootKey;
    IotCommStorageCallbacks_t            storage;
    IotCommRateLimitConfig_t             rateLimit;
    IotCommRateChallengeConfig_t         challenge;
    IotCommEventHandler_t                handler;
    void                                 *handlerCtx;
} IotCommConfig_t;

// Defines the network settings for the embedded server.
typedef struct IotCommServerConfig_s {
    uint16_t listenPort;
    uint16_t maxConnections;
    uint32_t maxPacketSize;
} IotCommServerConfig_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Initializes the IoT communication subsystem with the provided settings.
esp_err_t iotCommInit(IotCommConfig_t *config);
// Releases resources owned by the IoT communication subsystem.
void iotCommDeinit();

// Starts the IoT communication server with the given listener configuration.
esp_err_t iotCommStartServer(IotCommServerConfig_t *config);
// Stops the IoT communication server if it is running.
void iotCommStopServer();

// Reports whether the IoT communication server is currently accepting connections.
bool iotCommIsServerRunning();

// Associates arbitrary application data with a session.
esp_err_t iotCommSetSessionUserData(IotCommSessionHandle_t h, void *ptr, IotCommUserDataFreeFunc_t freeFn);
// Returns the application data currently attached to a session.
void* iotCommGetSessionUserData(IotCommSessionHandle_t h);

// Returns the internal identifier assigned to a session.
uint32_t iotCommGetSessionId(IotCommSessionHandle_t h);
// Returns the authenticated user identifier for a session.
uint32_t iotCommGetSessionUserId(IotCommSessionHandle_t h);
// Reports whether the session belongs to an administrator user.
bool  iotCommIsSessionUserAdmin(IotCommSessionHandle_t h);
// Returns the remote IP address associated with a session.
IPAddress_t iotCommGetSessionIpAddress(IotCommSessionHandle_t h);

// NOTE: Event replies are synchronous to the event callback. Do not retain event data
//       or defer completion to another task/core after the callback returns.
// Sends a successful reply for the current event callback.
esp_err_t iotCommEventReply(IotCommSessionHandle_t h, const uint8_t *reply, size_t replyLen);
// Sends an error reply for the current event callback.
esp_err_t iotCommEventReplyWithError(IotCommSessionHandle_t h, uint32_t code, const char *message);

// NOTE: This function sends a standard websocket close except if called within a session start
//       event. In this case, reason and message will act as the HTTP(S) Upgrade request response.
// NOTE: Like iotCommEventReply*, this must be completed synchronously from the callback.
// Closes a session or rejects it during the upgrade handshake.
void iotCommSessionClose(IotCommSessionHandle_t h, uint16_t reason, const char *message);

// Builds a configuration structure populated with library defaults.
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

// Builds a server configuration structure populated with library defaults.
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
// Stores the initial public key for the root user in persistent state.
esp_err_t iotCommInitRootUserPublicKey(const uint8_t publicKey[P256_PUBLIC_KEY_SIZE]);

#ifdef __cplusplus
}
#endif // __cplusplus
