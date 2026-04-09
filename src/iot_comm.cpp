#include "iot_comm/iot_comm.h"
#include "iot_comm/crypto/aes.h"
#include "iot_comm/crypto/hkdf.h"
#include "iot_comm/crypto/sha.h"
#include "iot_comm/crypto/utils.h"
#include "iot_comm/utils/binary.h"
#include "iot_comm/utils/network.h"
#include "challenge.h"
#include "http_helpers.h"
#include "rate_limit.h"
#include "user.h"
#include <convert.h>
#include <cJSON.h>
#include <endian.h>
#include <esp_check.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <growable_buffer.h>
#include <mutex.h>
#include <rundown_protection.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/_types.h>

static const char* TAG = "IotComm";

#define VERSION 1

#define TAG_LEN     16
#define AES_KEY_LEN 32

#define MAX_BODY_SIZE 10240
#define MAX_QUERY_SIZE 1024

#define CMD_CREATE_USER             0x7FF1
#define CMD_DELETE_USER             0x7FF2
#define CMD_RESET_USER_CREDENTIALS  0x7FF3
#define CMD_CHANGE_USER_CREDENTIALS 0x7FF4

#define SESSION_IV_LEN     12
#define SESSION_AES_KEY_LEN    32

#define MIN_WS_PACKET_SIZE 1024

#define MAX_OUTPUT_FRAME_SIZE 4096

// -----------------------------------------------------------------------------

typedef enum IncomingBufferType_e {
    IncomingBufferTypeNone = 0,
    IncomingBufferTypeBinary,
    IncomingBufferTypeText
} IncomingBufferType_t;

typedef struct ServerContext_s {
    size_t maxPacketSize;
    size_t maxConnectionsCount;

    struct {
        RwMutex_t mtx;
        struct SessionInfo_s *first;
        struct SessionInfo_s *last;
    } sessions;
} ServerContext_t;

typedef struct SessionInfo_s {
    struct SessionInfo_s *next;
    struct SessionInfo_s *prev;
    ServerContext_t *serverCtx;
    uint32_t id;
    int sockfd;
    void *userData;
    IotCommUserDataFreeFunc_t userDataFreeFn;
    IPAddress_t addr;
    uint32_t userId;
    uint32_t nextRxCounter;
    uint32_t nextTxCounter;
    ChallengeNonce_t nonce;
    AesContext_t clientAesCtx;
    uint8_t clientBaseIV[SESSION_IV_LEN];
    AesContext_t serverAesCtx;
    uint8_t serverBaseIV[SESSION_IV_LEN];
    uint8_t isAdmin : 1;
    uint8_t mustChangeCredentials : 1;
    uint8_t credentialsChangeAttempts : 2;
    uint8_t isClosed : 1;
    IncomingBufferType_t incomingMessageType;
    GrowableBuffer_t plaintextIn;
    GrowableBuffer_t ciphertextIn;
    GrowableBuffer_t ciphertextOut;
} SessionInfo_t;

// v(1) | cmd(2) | filler(1) | replyCounter(4) | counter(4) | filler(4)
typedef struct __attribute__((packed)) WebSocketPacketHeader_s {
    uint8_t  v;
    uint8_t  cmd[2];
    uint8_t  filler1;
    uint8_t  replyCounter[4];
    uint8_t  counter[4];
    uint32_t filler2;
} WebSocketPacketHeader_t;

typedef struct CommandContext_s {
    httpd_handle_t serverHandle;
    int sockfd;
    ServerContext_t *serverCtx;
    SessionInfo_t *session;
    uint16_t cmd;
    binary_reader_t br;
    uint32_t rxCounter;
} CommandContext_t;

typedef struct OnTheFlyEvent_s {
    SessionInfo_t *session;

    esp_err_t savedErr;
    bool      replySent;
    esp_err_t closeErr;
    bool      closeSent;

    IotCommEvent_t *event;

    httpd_req_t   *req;
    CommandContext_t *commandCtx;
} OnTheFlyEvent_t;

// -----------------------------------------------------------------------------

static RWMutex rwNtx;
static RundownProtection_t rp = RUNDOWN_PROTECTION_INIT_STATIC;
static IotCommEventHandler_t handler = nullptr;
static void *handlerCtx = nullptr;
static httpd_handle_t server = nullptr;
static _Atomic(uint32_t) nextSessionId = {0};

// -----------------------------------------------------------------------------

static void iotCommDeinitNoLock();
static void iotCommStopServerNoLock();

static esp_err_t serveWsInit(httpd_req_t *req);
static esp_err_t serveWsAuth(httpd_req_t *req);
static esp_err_t serveWs(httpd_req_t *req);
static esp_err_t serveWsUpgrade(httpd_req_t *req);
static esp_err_t serveWsPacket(httpd_req_t *req);

static esp_err_t handleCreateUser(CommandContext_t *commandCtx);
static esp_err_t handleDeleteUser(CommandContext_t *commandCtx);
static esp_err_t handleResetUserCredentials(CommandContext_t *commandCtx);
static esp_err_t handleChangeUserCredentials(CommandContext_t *commandCtx);
static esp_err_t handleCustomCommand(CommandContext_t *commandCtx);

static bool handleSessionStart(SessionInfo_t *session, httpd_req_t *req, esp_err_t *closeErr);
static void handleSessionEnd(SessionInfo_t *session);

static esp_err_t buildAndSendReply(CommandContext_t *commandCtx, const uint8_t *plaintextOut, size_t plaintextOutLen, uint32_t replyCounter,
                                   bool closeOnError);
static esp_err_t buildAndSendErrorReply(CommandContext_t *commandCtx, uint32_t code, const char *message, uint32_t replyCounter,
                                   bool closeOnError);

static esp_err_t closeWsWithCmdCtx(CommandContext_t *commandCtx, uint16_t code, const char *reason);
static esp_err_t closeWsWithCmdCtxAndError(CommandContext_t *commandCtx, const char *zone, esp_err_t err);

static void destroyServerCtx(void *ctx);
static void destroySessionCtx(void *ctx);

static SessionInfo_t *createSession();
static void destroySession(SessionInfo_t *session);

static esp_err_t readWsPacket(ServerContext_t *serverCtx, SessionInfo_t *session, httpd_req_t *req, bool *messageComplete);

static bool closeWs(httpd_handle_t serverHandle, int sockfd, uint16_t code, const char *reason);

static bool extGbAddB64(GrowableBuffer_t *buf, const uint8_t *src, size_t srcLen, bool isUrl);

// -----------------------------------------------------------------------------

esp_err_t iotCommInit(IotCommConfig_t *config)
{
    AutoRWMutex lock(rwNtx, false);
    UsersConfig_t usersConfig;
    uint8_t maxRequestsPerWindow;
    esp_err_t ret;

    if (!(config && config->handler)) {
        return ESP_ERR_INVALID_ARG;
    }

    iotCommDeinitNoLock();
    rundownProtInit(&rp);

    atomic_store_explicit(&nextSessionId, 1, memory_order_relaxed);

    // Initialize users manager
    memset(&usersConfig, 0, sizeof(usersConfig));
    usersConfig.maxUsersCount = config->maxUsersCount;
    usersConfig.rootKey.cb = config->rootKey.cb;
    usersConfig.rootKey.ctx = config->rootKey.ctx;
    usersConfig.storage.load = config->storage.load;
    usersConfig.storage.save = config->storage.save;
    usersConfig.storage.ctx = config->storage.ctx;
    ESP_GOTO_ON_ERROR(usersInit(&usersConfig), on_error, TAG, "Unable to initialize users manager");

    // The authentication flow is INIT+AUTH+WS so let's multiply the provided request limit by three.
    maxRequestsPerWindow = config->rateLimit.maxRequestsPerWindow;
    if (maxRequestsPerWindow < ((sizeof(maxRequestsPerWindow) << 8) - 1) / 3) {
        maxRequestsPerWindow *= 3;
    }
    else {
        maxRequestsPerWindow = (uint8_t)((sizeof(maxRequestsPerWindow) << 8) - 1);
    }
    ESP_GOTO_ON_ERROR(rateLimitInit(config->rateLimit.maxSlots, config->rateLimit.windowSizeInMs, maxRequestsPerWindow,
                                    config->rateLimit.maxConsecutiveAuthFailures),
                      on_error, TAG, "Unable to initialize rate limit handler");

    ESP_GOTO_ON_ERROR(challengesInit(config->challenge.maxSlots, config->challenge.windowSizeInMs), on_error, TAG,
                      "Unable to initialize challenges manager");

    // Save event handler
    handler = config->handler;
    handlerCtx = config->handlerCtx;

    // Done
    ESP_LOGI(TAG, "IotComm engine initialized");
    return ESP_OK;

on_error:
    iotCommDeinitNoLock();
    return ret;
}

void iotCommDeinit()
{
    rundownProtWait(&rp);

    {
        AutoRWMutex lock(rwNtx, false);

        iotCommDeinitNoLock();
    }
}

esp_err_t iotCommStartServer(IotCommServerConfig_t *config)
{
    AutoRWMutex lock(rwNtx, false);
    httpd_config_t httpdConfig;
    ServerContext_t *serverCtx;
    httpd_uri_t uri;
    esp_err_t err;

    if (!(config && config->listenPort >= 1 && config->maxConnections >= 1)) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!handler) {
        return ESP_ERR_INVALID_STATE;
    }

    iotCommStopServerNoLock();

    // Create http server context
    serverCtx = (ServerContext_t *)malloc(sizeof(ServerContext_t));
    if (!serverCtx) {
        err = ESP_ERR_NO_MEM;
        goto on_error;
    }
    memset(serverCtx, 0, sizeof(ServerContext_t));
    serverCtx->maxConnectionsCount = (size_t)config->maxConnections;
    serverCtx->maxPacketSize = (config->maxPacketSize > MIN_WS_PACKET_SIZE) ? (size_t)config->maxPacketSize : MIN_WS_PACKET_SIZE;
    rwMutexInit(&serverCtx->sessions.mtx);

    // Setup http server configuration
    httpdConfig = HTTPD_DEFAULT_CONFIG();
    httpdConfig.server_port = config->listenPort;
    httpdConfig.max_open_sockets = config->maxConnections;
    httpdConfig.keep_alive_enable = true;
    httpdConfig.keep_alive_idle = 10;
    httpdConfig.global_user_ctx = serverCtx;
    httpdConfig.global_user_ctx_free_fn = destroyServerCtx;

    // Start http server
    err = httpd_start(&server, &httpdConfig);
    if (err != ESP_OK) {
        destroyServerCtx(serverCtx);
        goto on_error;
    }

    // Setup URI handlers
    memset(&uri, 0, sizeof(uri));
    uri.uri = "/ws/init";
    uri.method = HTTP_POST;
    uri.handler = serveWsInit;
    err = httpd_register_uri_handler(server, &uri);
    if (err == ESP_OK) {
        uri.method = HTTP_OPTIONS;
        err = httpd_register_uri_handler(server, &uri);
    }
    if (err != ESP_OK) {
        goto on_error;
    }

    uri.uri = "/ws/auth";
    uri.method = HTTP_POST;
    uri.handler = serveWsAuth;
    err = httpd_register_uri_handler(server, &uri);
    if (err == ESP_OK) {
        uri.method = HTTP_OPTIONS;
        err = httpd_register_uri_handler(server, &uri);
    }
    if (err != ESP_OK) {
        goto on_error;
    }

    uri.uri = "/ws";
    uri.method = HTTP_GET;
    uri.handler = serveWs;
    uri.is_websocket = true;
    err = httpd_register_uri_handler(server, &uri);
    if (err == ESP_OK) {
        uri.method = HTTP_OPTIONS;
        err = httpd_register_uri_handler(server, &uri);
    }
    if (err != ESP_OK) {
        goto on_error;
    }

    // Done
    ESP_LOGI(TAG, "Server initialized and listening at %u", config->listenPort);
    return ESP_OK;

on_error:
    ESP_LOGE(TAG, "Unable to start http server. Error: %d.", err);
    iotCommStopServerNoLock();
    return err;
}

void iotCommStopServer()
{
    rundownProtWait(&rp);

    {
        AutoRWMutex lock(rwNtx, false);

        iotCommStopServerNoLock();
    }
}

bool iotCommIsServerRunning()
{
    AutoRWMutex lock(rwNtx, true);

    return !!server;
}

esp_err_t iotCommSetSessionUserData(IotCommSessionHandle_t h, void *ptr, IotCommUserDataFreeFunc_t freeFn)
{
    AutoRundownProtection rpLock(rp);
    void *oldUserData = nullptr;
    IotCommUserDataFreeFunc_t oldUserDataFreeFn = nullptr;

    if (rpLock.acquired()) {
        OnTheFlyEvent_t *otfe = (OnTheFlyEvent_t *)h;
        SessionInfo_t *session = otfe->session;

        // Save the old user data
        oldUserData = session->userData;
        oldUserDataFreeFn = session->userDataFreeFn;

        // Replace with new user data
        session->userData = ptr;
        session->userDataFreeFn = freeFn;
    }
    else {
        return ESP_ERR_INVALID_STATE;
    }

    // Free old user data
    if (oldUserData) {
        if (oldUserDataFreeFn) {
            oldUserDataFreeFn(oldUserData);
        }
        else {
            free(oldUserData);
        }
    }

    // Done
    return ESP_OK;
}

void* iotCommGetSessionUserData(IotCommSessionHandle_t h)
{
    AutoRundownProtection rpLock(rp);
    void *userData = nullptr;

    if (rpLock.acquired()) {
        OnTheFlyEvent_t *otfe = (OnTheFlyEvent_t *)h;

        userData = otfe->session->userData;
    }

    // Done
    return userData;
}

uint32_t iotCommGetSessionId(IotCommSessionHandle_t h)
{
    AutoRundownProtection rpLock(rp);
    uint32_t sessionId = 0;

    if (rpLock.acquired()) {
        OnTheFlyEvent_t *otfe = (OnTheFlyEvent_t *)h;

        sessionId = otfe->session->id;
    }

    // Done
    return sessionId;
}

uint32_t iotCommGetSessionUserId(IotCommSessionHandle_t h)
{
    AutoRundownProtection rpLock(rp);
    uint32_t userId = 0;

    if (rpLock.acquired()) {
        OnTheFlyEvent_t *otfe = (OnTheFlyEvent_t *)h;

        userId = otfe->session->userId;
    }

    // Done
    return userId;
}

bool  iotCommIsSessionUserAdmin(IotCommSessionHandle_t h)
{
    AutoRundownProtection rpLock(rp);
    bool isAdmin = false;

    if (rpLock.acquired()) {
        OnTheFlyEvent_t *otfe = (OnTheFlyEvent_t *)h;

        isAdmin = (otfe->session->isAdmin != 0) ? true : false;
    }

    // Done
    return isAdmin;
}

IPAddress_t iotCommGetSessionIpAddress(IotCommSessionHandle_t h)
{
    AutoRundownProtection rpLock(rp);
    IPAddress_t addr;

    if (rpLock.acquired()) {
        OnTheFlyEvent_t *otfe = (OnTheFlyEvent_t *)h;

        memcpy(&addr, &otfe->session->addr, sizeof(IPAddress_t));
    }
    else {
        memset(&addr, 0, sizeof(IPAddress_t));
    }

    // Done
    return addr;
}

esp_err_t iotCommEventReply(IotCommSessionHandle_t h, const uint8_t * reply, size_t replyLen)
{
    AutoRundownProtection rpLock(rp);

    if (rpLock.acquired()) {
        OnTheFlyEvent_t *otfe = (OnTheFlyEvent_t *)h;

        // If not a custom event command, nothing to do
        if (otfe->event->eventType != IotCommEventTypeCustomCommand) {
            return ESP_ERR_NOT_FOUND;
        }

        // If some error happened previously for this event, return it
        if (otfe->savedErr != ESP_OK) {
            return otfe->savedErr;
        }
        // If closed or a reply was already sent, block
        if (otfe->session->isClosed || otfe->replySent || otfe->closeSent) {
            return ESP_FAIL;
        }

        // Send the reply
        otfe->savedErr = buildAndSendReply(otfe->commandCtx, reply, replyLen, otfe->commandCtx->rxCounter, false);
        otfe->replySent = true;
        if (otfe->savedErr != ESP_OK) {
            otfe->closeSent = true;
            otfe->closeErr = closeWsWithCmdCtxAndError(otfe->commandCtx, "send-reply", otfe->savedErr);
        }

        // Done
        return otfe->savedErr;
    }

    // Rundown active
    return ESP_ERR_INVALID_STATE;
}

esp_err_t iotCommEventReplyWithError(IotCommSessionHandle_t h, uint32_t code, const char *message)
{
    AutoRundownProtection rpLock(rp);

    if (rpLock.acquired()) {
        OnTheFlyEvent_t *otfe = (OnTheFlyEvent_t *)h;

        // If not a custom event command, nothing to do
        if (otfe->event->eventType != IotCommEventTypeCustomCommand) {
            return ESP_ERR_NOT_FOUND;
        }

        // If some error happened previously for this event, return it
        if (otfe->savedErr != ESP_OK) {
            return otfe->savedErr;
        }
        // If closed or a reply was already sent, block
        if (otfe->session->isClosed || otfe->replySent || otfe->closeSent) {
            return ESP_FAIL;
        }

        // Send the reply
        otfe->savedErr = buildAndSendErrorReply(otfe->commandCtx, code, message, otfe->commandCtx->rxCounter, false);
        otfe->replySent = true;
        if (otfe->savedErr != ESP_OK) {
            otfe->closeSent = true;
            otfe->closeErr = closeWsWithCmdCtxAndError(otfe->commandCtx, "send-reply", otfe->savedErr);
        }

        // Done
        return otfe->savedErr;
    }

    // Rundown active
    return ESP_ERR_INVALID_STATE;
}

void iotCommSessionClose(IotCommSessionHandle_t h, uint16_t reason, const char *message)
{
    AutoRundownProtection rpLock(rp);

    if (rpLock.acquired()) {
        OnTheFlyEvent_t *otfe = (OnTheFlyEvent_t *)h;

        // If not a custom event command, nothing to do
        switch (otfe->event->eventType) {
            case IotCommEventTypeSessionStart:
                if (!otfe->closeSent) {
                    if (reason < 400) {
                        reason = (uint16_t)HTTPD_500_INTERNAL_SERVER_ERROR;
                    }
                    if (message && *message == 0) {
                        message = nullptr;
                    }

                    otfe->closeSent = true;
                    otfe->closeErr = httpd_resp_send_err(otfe->req, (httpd_err_code_t)reason, message);
                }
                break;

            case IotCommEventTypeSessionEnd:
                break;

            case IotCommEventTypeCustomCommand:
                if (!(otfe->session->isClosed || otfe->closeSent)) {
                    otfe->closeSent = true;
                    otfe->closeErr = closeWsWithCmdCtx(otfe->commandCtx, reason, message);
                }
                break;
        }
    }
}

esp_err_t iotCommInitRootUserPublicKey(const uint8_t publicKey[P256_PUBLIC_KEY_SIZE])
{
    AutoRWMutex lock(rwNtx, true);
    uint32_t rootUserId;

    if (!handler) {
        return ESP_ERR_INVALID_STATE;
    }

    rootUserId = userGetID("root", 4);
    return userChangeCredentials(rootUserId, rootUserId, publicKey);
}

// -----------------------------------------------------------------------------

static void iotCommDeinitNoLock()
{
    iotCommStopServerNoLock();

    challengesDeinit();
    rateLimitDeinit();
    usersDeinit();

    handler = nullptr;
    handlerCtx = nullptr;
}

static void iotCommStopServerNoLock()
{
    if (server) {
        httpd_stop(server);
        server = nullptr;
    }
}

static esp_err_t serveWsInit(httpd_req_t *req)
{
    AutoRundownProtection rpLock(rp);
    IPAddress_t remoteAddr;
    GrowableBuffer_t reqBody;
    GrowableBuffer_t respBody;
    cJSON *json = nullptr;
    char *userNameValue, *clientNonceValue, *ecdhClientPublicKeyValue;
    size_t clientNonceLen;
    size_t ecdhClientPublicKeyLen;
    Challenge_t challenge;
    ChallengeCookie_t challengeCookie;
    P256KeyPair_t ecdhKeyPair;
    esp_err_t err;

    if (!rpLock.acquired()) {
        return ESP_ERR_INVALID_STATE;
    }

    // Is OPTIONS?
    if (req->method == HTTP_OPTIONS) {
        return httpSendPreflightResponse(req);
    }

    // Prepare
    reqBody = GB_STATIC_INIT;
    respBody = GB_STATIC_INIT;
    p256KeyPairInit(&ecdhKeyPair);
    memset(&challenge, 0, sizeof(challenge));

    // Send CORS
    err = httpSendDefaultCORS(req);
    if (err != ESP_OK) {
        goto done;
    }

    // Get request IP address
    if (!httpGetClientIpFromRequest(req, &remoteAddr)) {
        ESP_LOGE(TAG, "Failed to get client IP address");
        err = ESP_FAIL;
        goto done;
    }

    // Check rate limit
    if (!rateLimitCheckRequest(&remoteAddr)) {
        err = httpd_resp_send_custom_err(req, "429 Too Many Requests", "");
        goto done;
    }

    // Read request body
    if (req->content_len > MAX_BODY_SIZE) {
        err = httpd_resp_send_err(req, HTTPD_413_CONTENT_TOO_LARGE, nullptr);
        goto done;
    }
    err = httpGetRequestBody(&reqBody, req);
    if (err != ESP_OK) {
        goto done;
    }

    // Extract parameters from request body and validate
    json = cJSON_ParseWithLength((const char*)reqBody.buffer, reqBody.used);
    if (!json) {
error_invalid_data:
        err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid parameters");
        goto done;
    }

    userNameValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "userName"));
    clientNonceValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "clientNonce"));
    ecdhClientPublicKeyValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "clientPublicKey"));
    if ((!userNameValue) || *userNameValue == 0 || (!clientNonceValue) || (!ecdhClientPublicKeyValue)) {
        goto error_invalid_data;
    }

    // Validate user
    challenge.userId = userGetID(userNameValue, strlen(userNameValue));
    if (challenge.userId == 0) {
        goto error_invalid_data;
    }

    // Decode and validate client nonce and client ECDH public key
    clientNonceLen = sizeof(challenge.clientNonce);
    ecdhClientPublicKeyLen = sizeof(challenge.ecdhClientPublicKey);
    if (
        (!fromB64(clientNonceValue, strlen(clientNonceValue), false, challenge.clientNonce, &clientNonceLen)) ||
        (!fromB64(ecdhClientPublicKeyValue, strlen(ecdhClientPublicKeyValue), false, challenge.ecdhClientPublicKey,
                  &ecdhClientPublicKeyLen))
    ) {
        goto error_invalid_data;
    }
    if (
        clientNonceLen != CHALLENGE_NONCE_SIZE || ecdhClientPublicKeyLen != P256_PUBLIC_KEY_SIZE ||
        (!p256ValidatePublicKey(challenge.ecdhClientPublicKey, P256_PUBLIC_KEY_SIZE))
    ) {
        goto error_invalid_data;
    }

    // Generate server nonce, challenge cookie and ephemeral server ECDH key pair
    if (
        randomize(challenge.serverNonce, sizeof(challenge.serverNonce)) != ESP_OK ||
        randomize(challengeCookie, sizeof(challengeCookie)) != ESP_OK ||
        ecdhGeneratePair(&ecdhKeyPair) != ESP_OK ||
        p256SavePublicKey(&ecdhKeyPair, challenge.ecdhServerPublicKey) != ESP_OK ||
        p256SavePrivateKey(&ecdhKeyPair, challenge.ecdhServerPrivateKey) != ESP_OK
    ) {
        err = ESP_FAIL;
        goto done;
    }

    // Add the new challenge
    challengesAdd(challengeCookie, &remoteAddr, &challenge);

    // Prepare output
    if (
        (!gbAdd(&respBody, "{\"token\":\"", 10)) ||
        (!extGbAddB64(&respBody, challengeCookie, sizeof(challengeCookie), false)) ||
        (!gbAdd(&respBody, "\",\"serverNonce\":\"", 17)) ||
        (!extGbAddB64(&respBody, challenge.serverNonce, sizeof(challenge.serverNonce), false)) ||
        (!gbAdd(&respBody, "\",\"serverPublicKey\":\"", 21)) ||
        (!extGbAddB64(&respBody, challenge.ecdhServerPublicKey, sizeof(challenge.ecdhServerPublicKey), false)) ||
        (!gbAdd(&respBody, "\"}", 2))
    ) {
        err = ESP_ERR_NO_MEM;
        goto done;
    }

    // Send response
    err = httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        err = httpd_resp_send(req, (char *)respBody.buffer, (ssize_t)respBody.used);
    }

done:
    // Cleanup
    if (json) {
        cJSON_Delete(json);
    }
    memset(&challenge, 0, sizeof(challenge));
    p256KeyPairDone(&ecdhKeyPair);
    gbWipe(&respBody);
    gbReset(&respBody, true);
    gbWipe(&reqBody);
    gbReset(&reqBody, true);

    // Done
    return httpSendInternalErrorResponse(req, err, nullptr);
}

static esp_err_t serveWsAuth(httpd_req_t *req)
{
    AutoRundownProtection rpLock(rp);
    IPAddress_t remoteAddr;
    GrowableBuffer_t reqBody;
    GrowableBuffer_t respBody;
    cJSON *json = nullptr;
    char *cookieValue, *authNonceValue, *signatureValue;
    ChallengeCookie_t challengeCookie;
    bool removeChallenge = false;
    uint8_t authNonce[CHALLENGE_NONCE_SIZE];
    uint8_t signature[P256_SIGNATURE_SIZE];
    size_t challengeCookieLen;
    size_t authNonceLen;
    size_t signatureLen;
    Challenge_t *challenge;
    Sha256Context_t sha256Ctx;
    uint8_t th[SHA256_SIZE];
    bool b;
    esp_err_t err;

    if (!rpLock.acquired()) {
        return ESP_ERR_INVALID_STATE;
    }

    // Is OPTIONS?
    if (req->method == HTTP_OPTIONS) {
        return httpSendPreflightResponse(req);
    }

    // Prepare
    reqBody = GB_STATIC_INIT;
    respBody = GB_STATIC_INIT;
    sha256Init(&sha256Ctx);

    // Send CORS
    err = httpSendDefaultCORS(req);
    if (err != ESP_OK) {
        goto done;
    }

    // Get request IP address
    if (!httpGetClientIpFromRequest(req, &remoteAddr)) {
        ESP_LOGE(TAG, "Failed to get client IP address");
        err = ESP_FAIL;
        goto done;
    }

    // Check rate limit
    if (!rateLimitCheckRequest(&remoteAddr)) {
        err = httpd_resp_send_custom_err(req, "429 Too Many Requests", "");
        goto done;
    }

    // Read request body
    if (req->content_len > MAX_BODY_SIZE) {
        err = httpd_resp_send_err(req, HTTPD_413_CONTENT_TOO_LARGE, nullptr);
        goto done;
    }
    err = httpGetRequestBody(&reqBody, req);
    if (err != ESP_OK) {
        goto done;
    }

    // Extract parameters from request body and validate
    json = cJSON_ParseWithLength((const char*)reqBody.buffer, reqBody.used);
    if (!json) {
error_invalid_data:
        err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid parameters");
        goto done;
    }

    cookieValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "token"));
    authNonceValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "authNonce"));
    signatureValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "signature"));
    if ((!cookieValue) || (!authNonceValue) || (!signatureValue)) {
        goto error_invalid_data;
    }

    // Decode and validate token, auth nonce, and signature
    challengeCookieLen = sizeof(challengeCookie);
    authNonceLen = sizeof(authNonce);
    signatureLen = sizeof(signature);
    if (
        (!fromB64(cookieValue, strlen(cookieValue), false, challengeCookie, &challengeCookieLen)) ||
        (!fromB64(authNonceValue, strlen(authNonceValue), false, authNonce, &authNonceLen)) ||
        (!fromB64(signatureValue, strlen(signatureValue), false, signature, &signatureLen))
    ) {
        goto error_invalid_data;
    }
    if (challengeCookieLen != CHALLENGE_COOKIE_SIZE || authNonceLen != CHALLENGE_NONCE_SIZE || signatureLen != P256_SIGNATURE_SIZE) {
        goto error_invalid_data;
    }

    // Lookup challenge
    challenge = challengesFind(challengeCookie, &remoteAddr);
    if (!challenge) {
error_not_auth:
        err = httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, nullptr);
        goto done;
    }
    removeChallenge = true;

    // th = SHA256("ws-login-v1" || c_pk || s_pk || s_nonce || c_nonce || cookie || auth_nonce)
    err = sha256Start(&sha256Ctx);
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, (const uint8_t *)"ws-login-v1", 11);
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, challenge->ecdhServerPublicKey, sizeof(challenge->ecdhServerPublicKey));
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, challenge->ecdhClientPublicKey, sizeof(challenge->ecdhClientPublicKey));
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, challenge->serverNonce, sizeof(challenge->serverNonce));
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, challenge->clientNonce, sizeof(challenge->clientNonce));
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, challengeCookie, sizeof(challengeCookie));
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, authNonce, sizeof(authNonce));
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Finish(&sha256Ctx, th);
    if (err != ESP_OK) {
        goto done;
    }

    // Verify signature of th
    err = userVerifySignature(challenge->userId, th, signature);
    if (err != ESP_OK) {
        if (err == ESP_ERR_NOT_FOUND || err == ESP_ERR_SIGNATURE_VERIFICATION_FAILED || err == ESP_ERR_INVALID_STATE) {
            challengesRemove(challengeCookie);
            goto error_not_auth;
        }
        goto done;
    }

    // Mark challenge as verified
    challenge->verified = true;

    // Generate ws nonce
    err = randomize(challenge->wsNonce, sizeof(challenge->wsNonce));
    if (err != ESP_OK) {
        goto done;
    }

    // Prepare output
    if (!(gbAdd(&respBody, "{\"mustChangeCredentials\":", 25))) {
error_no_mem:
        err = ESP_ERR_NO_MEM;
        goto done;
    }
    userMustChangeCredentials(challenge->userId, &b); // error check ignored on purpose
    if (b) {
        if (!gbAdd(&respBody, "true", 4)) {
            goto error_no_mem;
        }
    }
    else {
        if (!gbAdd(&respBody, "false", 5)) {
            goto error_no_mem;
        }
    }
    if (
        (!gbAdd(&respBody, ",\"wsNonce\":\"", 12)) ||
        (!extGbAddB64(&respBody, challenge->wsNonce, sizeof(challenge->wsNonce), false)) ||
        (!gbAdd(&respBody, "\"}", 2))
    ) {
        goto error_no_mem;
    }

    // Send response
    err = httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        err = httpd_resp_send(req, (char *)respBody.buffer, (ssize_t)respBody.used);
    }

    // On success, keep added challenge
    removeChallenge = false;

done:
    // Cleanup
    if (removeChallenge) {
        challengesRemove(challengeCookie);
    }
    if (json) {
        cJSON_Delete(json);
    }
    memset(th, 0, sizeof(th));
    memset(signature, 0, sizeof(signature));
    memset(authNonce, 0, sizeof(authNonce));
    memset(&challengeCookie, 0, sizeof(challengeCookie));
    sha256Done(&sha256Ctx);
    gbWipe(&respBody);
    gbReset(&respBody, true);
    gbWipe(&reqBody);
    gbReset(&reqBody, true);

    // Done
    return httpSendInternalErrorResponse(req, err, nullptr);
}

static esp_err_t serveWs(httpd_req_t *req)
{
    AutoRundownProtection rpLock(rp);

    if (!rpLock.acquired()) {
        return ESP_ERR_INVALID_STATE;
    }

    if (req->method == 0) {
        return serveWsPacket(req);
    }
    return serveWsUpgrade(req);
}

static esp_err_t serveWsUpgrade(httpd_req_t *req)
{
    ServerContext_t *serverCtx = (ServerContext_t *)httpd_get_global_user_ctx(req->handle);
    IPAddress_t remoteAddr;
    GrowableBuffer_t reqQueryParams;
    char tokenB64[CHALLENGE_COOKIE_SIZE * 4 / 3 + 2];
    char wsNonceB64[CHALLENGE_NONCE_SIZE * 4 / 3 + 2];
    char signatureB64[P256_SIGNATURE_SIZE * 4 / 3 + 2];
    ChallengeCookie_t challengeCookie;
    bool removeChallenge = false;
    ChallengeNonce_t wsNonce;
    uint8_t signature[P256_SIGNATURE_SIZE];
    size_t challengeCookieLen;
    size_t wsNonceLen;
    size_t signatureLen;
    Challenge_t *challenge;
    Sha256Context_t sha256Ctx;
    uint8_t th[SHA256_SIZE];
    P256KeyPair_t ecdhKeyPair;
    uint8_t info[6 + 2 * P256_PUBLIC_KEY_SIZE];
    uint8_t salt[SHA256_SIZE];
    uint8_t sharedSecret[AES_KEY_LEN];
    uint8_t derivedKey[2 * AES_KEY_LEN + 2 * SESSION_IV_LEN];
    SessionInfo_t *session;
    bool b;
    esp_err_t err;

    // Is OPTIONS?
    if (req->method == HTTP_OPTIONS) {
        return httpSendPreflightResponse(req);
    }

    // Prepare
    reqQueryParams = GB_STATIC_INIT;
    sha256Init(&sha256Ctx);
    p256KeyPairInit(&ecdhKeyPair);

    // Send CORS
    err = httpSendDefaultCORS(req);
    if (err != ESP_OK) {
        goto done;
    }

    // Check if it is a real websocket request. ESP_HTTP_SERVER calls the handle even
    // when not a websocket connection
    if (httpd_req_get_hdr_value_len(req, "Upgrade") == 0) {
        err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Not a websocket request");
        goto done;
    }

    // Get request IP address
    if (!httpGetClientIpFromRequest(req, &remoteAddr)) {
        ESP_LOGE(TAG, "Failed to get client IP address");
        err = ESP_FAIL;
        goto done;
    }

    // Check rate limit
    if (!rateLimitCheckRequest(&remoteAddr)) {
        err = httpd_resp_send_custom_err(req, "429 Too Many Requests", "");
        goto done;
    }

    // Read request quey
    err = httpGetRequestQueryParams(&reqQueryParams, req, MAX_QUERY_SIZE);
    if (err != ESP_OK) {
        if (err == ESP_ERR_INVALID_SIZE) {
            err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Query too long");
        }
        goto done;
    }

    // Extract parameters from url query
    if (
        httpd_query_key_value((const char*)reqQueryParams.buffer, "token", tokenB64, sizeof(tokenB64)) != ESP_OK ||
        httpd_query_key_value((const char*)reqQueryParams.buffer, "wsNonce", wsNonceB64, sizeof(wsNonceB64)) != ESP_OK ||
        httpd_query_key_value((const char*)reqQueryParams.buffer, "signature", signatureB64, sizeof(signatureB64)) != ESP_OK
    ) {
error_invalid_data:
        err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid parameters");
        goto done;
    }

    // Validate parameters
    challengeCookieLen = sizeof(challengeCookie);
    wsNonceLen = sizeof(wsNonce);
    signatureLen = sizeof(signature);
    if (
        (!fromB64(tokenB64, strlen(tokenB64), true, challengeCookie, &challengeCookieLen)) || challengeCookieLen != CHALLENGE_COOKIE_SIZE ||
        (!fromB64(wsNonceB64, strlen(wsNonceB64), true, wsNonce, &wsNonceLen)) || wsNonceLen != CHALLENGE_NONCE_SIZE ||
        (!fromB64(signatureB64, strlen(signatureB64), true, signature, &signatureLen)) ||signatureLen != P256_SIGNATURE_SIZE
    ) {
        goto error_invalid_data;
    }

    // Lookup challenge and check if the user is authenticated
    challenge = challengesFind(challengeCookie, &remoteAddr);
    if (!challenge) {
error_not_auth:
        err = httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, nullptr);
        goto done;
    }
    removeChallenge = true;

    if ((!challenge->verified) ||
        (!constantTimeCompare(challenge->wsNonce, wsNonce, CHALLENGE_NONCE_SIZE))
    ) {
        goto error_not_auth;
    }

    // th = SHA256("ws-login-v1" || s_nonce || c_nonce || cookie || ws_nonce)
    err = sha256Start(&sha256Ctx);
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, (const uint8_t *)"ws-login-v1", 11);
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, challenge->serverNonce, sizeof(challenge->serverNonce));
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, challenge->clientNonce, sizeof(challenge->clientNonce));
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, challengeCookie, sizeof(challengeCookie));
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, wsNonce, sizeof(wsNonce));
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Finish(&sha256Ctx, th);
    if (err != ESP_OK) {
        goto done;
    }

    // Verify signature of th
    err = userVerifySignature(challenge->userId, th, signature);
    if (err != ESP_OK) {
        if (err == ESP_ERR_NOT_FOUND || err == ESP_ERR_SIGNATURE_VERIFICATION_FAILED || err == ESP_ERR_INVALID_STATE) {
            challengesRemove(challengeCookie);
            goto error_not_auth;
        }
        goto done;
    }

    // Build info
    memcpy(info, "mx-iot", 6);
    memcpy(info + 6, challenge->ecdhServerPublicKey, sizeof(challenge->ecdhServerPublicKey));
    memcpy(info + 6 + sizeof(challenge->ecdhServerPublicKey), challenge->ecdhClientPublicKey, sizeof(challenge->ecdhClientPublicKey));

    // Build salt = SHA256("ws-login-v1" || s_nonce || c_nonce || cookie)
    err = sha256Start(&sha256Ctx);
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, (const uint8_t *)"ws-login-v1", 11);
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, challenge->serverNonce, sizeof(challenge->serverNonce));
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, challenge->clientNonce, sizeof(challenge->clientNonce));
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Update(&sha256Ctx, challengeCookie, sizeof(challengeCookie));
    if (err != ESP_OK) {
        goto done;
    }
    err = sha256Finish(&sha256Ctx, salt);
    if (err != ESP_OK) {
        goto done;
    }

    // Compute shared secret and derive keys
    err = p256LoadPrivateKey(&ecdhKeyPair, challenge->ecdhServerPrivateKey);
    if (err == ESP_OK) {
        err = p256LoadPublicKey(&ecdhKeyPair, challenge->ecdhClientPublicKey);
        if (err == ESP_OK) {
            err = ecdhComputeSharedSecret(&ecdhKeyPair, sharedSecret);
        }
    }
    if (err != ESP_OK) {
        goto done;
    }
    err = hkdfSha256DeriveKey(sharedSecret, AES_KEY_LEN, salt, sizeof(salt), info, sizeof(info), derivedKey, sizeof(derivedKey));
    if (err != ESP_OK) {
        goto done;
    }

    // Get server context
    serverCtx = (ServerContext_t *)httpd_get_global_user_ctx(req->handle);

    // Create user session
    session = createSession();
    if (!session) {
        err = ESP_ERR_NO_MEM;
        goto done;
    }
    session->serverCtx = serverCtx;
    session->sockfd = httpd_req_to_sockfd(req);
    memcpy(&session->addr, &remoteAddr, sizeof(remoteAddr));
    session->userId = challenge->userId;
    session->nextRxCounter = 1;
    session->nextTxCounter = 1;

    memcpy(session->nonce, challenge->wsNonce, sizeof(ChallengeNonce_t));
    err = aesSetKey(&session->clientAesCtx, derivedKey, AES_KEY_LEN);
    if (err != ESP_OK) {
error_destroy_session_and_done:
        destroySession(session);
        goto done;
    }
    err = aesSetKey(&session->serverAesCtx, derivedKey + AES_KEY_LEN, AES_KEY_LEN);
    if (err != ESP_OK) {
        goto error_destroy_session_and_done;
    }
    memcpy(session->clientBaseIV, derivedKey + 2 * AES_KEY_LEN, SESSION_IV_LEN);
    memcpy(session->serverBaseIV, derivedKey + 2 * AES_KEY_LEN + SESSION_IV_LEN, SESSION_IV_LEN);

    err = userIsAdmin(session->userId, &b);
    if (err != ESP_OK) {
        goto error_destroy_session_and_done;
    }
    session->isAdmin = (b) ? 1 : 0;

    err = userMustChangeCredentials(session->userId, &b);
    if (err != ESP_OK) {
        goto error_destroy_session_and_done;
    }
    session->mustChangeCredentials = (b) ? 1 : 0;

    // Bind our internal session to the connection
    httpd_sess_set_ctx(req->handle, session->sockfd, session, destroySessionCtx);

    // Add the session to the server's sessions list
    rwMutexLockWrite(&serverCtx->sessions.mtx);
    session->prev = serverCtx->sessions.last;
    if (serverCtx->sessions.last) {
        serverCtx->sessions.last->next = session;
    }
    else {
        serverCtx->sessions.first = session;
    }
    serverCtx->sessions.last = session;
    rwMutexUnlockWrite(&serverCtx->sessions.mtx);

    // Call session start callback
    if (handleSessionStart(session, req, &err)) {
        goto done;
    }

    // Look for existing sessions for the same user and close them
    rwMutexLockRead(&serverCtx->sessions.mtx);
    for (SessionInfo_t *otherSession = serverCtx->sessions.first;
         otherSession;
         otherSession = otherSession->next
    ) {
        // Dont close our own session
        if (otherSession->sockfd == session->sockfd) {
            continue;
        }

        if (otherSession->userId == session->userId) {
            ESP_LOGD(TAG, "Closing old session %u for user %u", otherSession->id, otherSession->userId);
            otherSession->isClosed = true;
            closeWs(req->handle, otherSession->sockfd, WS_CLOSE_GOING_AWAY, "New connection detected");
        }
    }
    rwMutexUnlockRead(&serverCtx->sessions.mtx);

    // Reset rate limits for successful access
    rateLimitResetAddress(&remoteAddr);

    // Upgrade to WebSockets
    err = ESP_OK;

done:
    // Cleanup
    if (removeChallenge) {
        challengesRemove(challengeCookie);
    }
    memset(derivedKey, 0, sizeof(derivedKey));
    memset(sharedSecret, 0, sizeof(sharedSecret));
    memset(salt, 0, sizeof(salt));
    memset(info, 0, sizeof(info));
    wsNonceLen = challengeCookieLen = 0;
    memset(wsNonce, 0, sizeof(wsNonce));
    memset(challengeCookie, 0, sizeof(challengeCookie));
    memset(wsNonceB64, 0, sizeof(wsNonceB64));
    memset(tokenB64, 0, sizeof(tokenB64));
    p256KeyPairDone(&ecdhKeyPair);
    sha256Done(&sha256Ctx);
    gbWipe(&reqQueryParams);
    gbReset(&reqQueryParams, true);

    // Done
    return httpSendInternalErrorResponse(req, err, nullptr);
}

static esp_err_t serveWsPacket(httpd_req_t *req)
{
    uint8_t iv[SESSION_IV_LEN];
    WebSocketPacketHeader_t *hdr;
    size_t dataAndTagLen;
    CommandContext_t commandCtx;
    bool messageComplete;
    esp_err_t err;

    // Get session from session context
    commandCtx.serverCtx = (ServerContext_t *)httpd_get_global_user_ctx(req->handle);
    commandCtx.serverHandle = req->handle;
    commandCtx.sockfd = httpd_req_to_sockfd(req);
    commandCtx.session = (SessionInfo_t *)httpd_sess_get_ctx(commandCtx.serverHandle, commandCtx.sockfd);
    if (!commandCtx.session) {
        ESP_LOGD(TAG, "Session not found.");
        return closeWsWithCmdCtx(&commandCtx, WS_CLOSE_APP_SESSION_NOT_FOUND, nullptr);
    }

    // Check if already closed
    if (commandCtx.session->isClosed) {
        return ESP_OK;
    }

    // Read WebSocket packet
    err = readWsPacket(commandCtx.serverCtx, commandCtx.session, req, &messageComplete);
    if (err != ESP_OK) {
        if (err == ESP_ERR_INVALID_STATE || err == ESP_ERR_INVALID_SIZE || err == ESP_ERR_NOT_SUPPORTED) {
            ESP_LOGD(TAG, "Invalid or unexpected WebSocket packet. Error: %ld.", err);
        }
        else {
            ESP_LOGD(TAG, "Unable to read WebSocket packet. Error: %ld.", err);
        }
        return closeWsWithCmdCtxAndError(&commandCtx, "read", err);
    }
    if (!messageComplete) {
        // Nothing to do if the message is not complete
        return ESP_OK;
    }

    // We only accept binary messages
    if (commandCtx.session->incomingMessageType != IncomingBufferTypeBinary) {
        ESP_LOGD(TAG, "Non binary packet.");
        return closeWsWithCmdCtx(&commandCtx, WS_CLOSE_UNSUPPORTED_DATA, nullptr);
    }

    // Check message size (the payload must be, at least, 1 byte plus the TAG)
    if (commandCtx.session->ciphertextIn.used <= sizeof(WebSocketPacketHeader_t) + TAG_LEN) {
        ESP_LOGD(TAG, "Short packet.");
        return closeWsWithCmdCtx(&commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }

    // Extract header and validate version and RX counter (a.k.a. nonce)
    hdr = (WebSocketPacketHeader_t *)commandCtx.session->ciphertextIn.buffer;
    if (hdr->v != VERSION) {
        ESP_LOGD(TAG, "Unsupported version packet.");
        return closeWsWithCmdCtx(&commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }
    commandCtx.rxCounter = be32dec(hdr->counter);
    if (commandCtx.session->nextRxCounter != commandCtx.rxCounter) {
        ESP_LOGD(TAG, "Counter mismatch.");
        return closeWsWithCmdCtx(&commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }
    commandCtx.session->nextRxCounter += 1;
    commandCtx.cmd = be16dec(hdr->cmd);
    dataAndTagLen = commandCtx.session->ciphertextIn.used - sizeof(WebSocketPacketHeader_t);

    // Build IV
    memcpy(iv, commandCtx.session->clientBaseIV, SESSION_IV_LEN);
    for (size_t i = 0; i < 4; i++) {
        iv[SESSION_IV_LEN-i-1] ^= (uint8_t)((commandCtx.rxCounter >> (i << 3)) & 0xFF);
    }

    // Prepare output for decrypted message
    gbReset(&commandCtx.session->plaintextIn, false);
    if (!gbEnsureSize(&commandCtx.session->plaintextIn, dataAndTagLen - TAG_LEN)) {
        return closeWsWithCmdCtxAndError(&commandCtx, "read", ESP_ERR_NO_MEM);
    }

    // Decrypt message
    err = aesDecrypt(&commandCtx.session->clientAesCtx, commandCtx.session->ciphertextIn.buffer + sizeof(WebSocketPacketHeader_t),
                     dataAndTagLen, iv, sizeof(iv), nullptr, 0, commandCtx.session->plaintextIn.buffer);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Unable to decrypt message. Error: %ld.", err);
        if (err == MBEDTLS_ERR_GCM_AUTH_FAILED) {
            return closeWsWithCmdCtx(&commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
        }
        return closeWsWithCmdCtxAndError(&commandCtx, "decode", err);
    }

    // Cleanup incoming message internals
    commandCtx.session->incomingMessageType = IncomingBufferTypeNone;
    gbReset(&commandCtx.session->ciphertextIn, false);

    // Check if the only accepted command is to change the credentials
    if (commandCtx.session->mustChangeCredentials != 0 && commandCtx.cmd != CMD_CHANGE_USER_CREDENTIALS) {
        ESP_LOGD(TAG, "User must change the access credentials.");
        return closeWsWithCmdCtx(&commandCtx, WS_CLOSE_APP_CREDENTIALS_CHANGE_MANDATORY, "User must change the access credentials.");
    }

    commandCtx.br = br_init(commandCtx.session->plaintextIn.buffer, dataAndTagLen - TAG_LEN);
    switch (commandCtx.cmd) {
        case CMD_CREATE_USER:
            return handleCreateUser(&commandCtx);

        case CMD_DELETE_USER:
            return handleDeleteUser(&commandCtx);

        case CMD_RESET_USER_CREDENTIALS:
            return handleResetUserCredentials(&commandCtx);

        case CMD_CHANGE_USER_CREDENTIALS:
            return handleChangeUserCredentials(&commandCtx);
    }

    // Custom command received
    return handleCustomCommand(&commandCtx);
}

static esp_err_t handleCreateUser(CommandContext_t *commandCtx)
{
    const char *name;
    size_t nameLen;
    const uint8_t *publicKey;
    uint8_t publicKeyBuf[P256_PUBLIC_KEY_SIZE];

    if (commandCtx->session->isAdmin == 0) {
        ESP_LOGD(TAG, "CREATE USER command: Insufficient privileges.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Insufficient privileges", commandCtx->rxCounter, true);
    }

    // Get user name
    if ((!br_read_str(&commandCtx->br, &name, &nameLen)) || nameLen == 0) {
        ESP_LOGD(TAG, "CREATE USER command: Invalid packet.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }

    // Get the new public key
    if (!br_read_blob(&commandCtx->br, P256_PUBLIC_KEY_SIZE, &publicKey)) {
        ESP_LOGD(TAG, "CREATE USER command: Invalid packet.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }
    memcpy(publicKeyBuf, publicKey, P256_PUBLIC_KEY_SIZE);

    // Check if the user already exists
    if (userCreate(name, nameLen, publicKeyBuf) == 0) {
        ESP_LOGD(TAG, "CREATE USER command: Unable to create new user.");
        return buildAndSendErrorReply(commandCtx, ESP_FAIL, "Unable to create new user", commandCtx->rxCounter, true);
    }

    // Done
    ESP_LOGD(TAG, "CREATE USER command: User successfully created.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, commandCtx->rxCounter, true);
}

static esp_err_t handleDeleteUser(CommandContext_t *commandCtx)
{
    const char *name;
    size_t nameLen;
    uint32_t targetUserId;
    bool isAdmin = false;

    if (commandCtx->session->isAdmin == 0) {
        ESP_LOGD(TAG, "DELETE USER command: Insufficient privileges.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Insufficient privileges", commandCtx->rxCounter, true);
    }

    // Get user name
    if ((!br_read_str(&commandCtx->br, &name, &nameLen)) || nameLen == 0) {
        ESP_LOGD(TAG, "DELETE USER command: Invalid packet.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }

    // Find the user
    targetUserId = userGetID(name, nameLen);
    if (targetUserId == 0 || userIsAdmin(targetUserId, &isAdmin) != ESP_OK) {
        ESP_LOGD(TAG, "DELETE USER command: User not found.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_FOUND, "User not found", commandCtx->rxCounter, true);
    }

    // Check if the user is admin
    if (isAdmin) {
        ESP_LOGD(TAG, "DELETE USER command: Cannot delete administrator.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Cannot delete admin user", commandCtx->rxCounter, true);
    }

    // Delete it
    userDestroy(targetUserId);

    // Delete active target user sessions
    rwMutexLockRead(&commandCtx->serverCtx->sessions.mtx);
    for (SessionInfo_t *otherSession = commandCtx->serverCtx->sessions.first; otherSession; otherSession = otherSession->next) {
        // Dont close our own session
        if (otherSession->sockfd == commandCtx->sockfd) {
            continue;
        }

        if (otherSession->userId == targetUserId) {
            ESP_LOGD(TAG, "Closing session %u for deleted user %u", otherSession->id, otherSession->userId);
            otherSession->isClosed = true;
            closeWs(commandCtx->serverHandle, otherSession->sockfd, WS_CLOSE_GOING_AWAY, "User has been deleted");
        }
    }
    rwMutexUnlockRead(&commandCtx->serverCtx->sessions.mtx);

    // Done
    ESP_LOGD(TAG, "DELETE USER command: User successfully deleted.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, commandCtx->rxCounter, true);
}

static esp_err_t handleResetUserCredentials(CommandContext_t *commandCtx)
{
    const char *name;
    size_t nameLen;
    uint32_t targetUserId;
    bool targetIsAdmin;
    const uint8_t *publicKey;
    uint8_t publicKeyBuf[P256_PUBLIC_KEY_SIZE];

    if (commandCtx->session->isAdmin == 0) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: Insufficient privileges.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Insufficient privileges", commandCtx->rxCounter, true);
    }

    // Get user name
    if ((!br_read_str(&commandCtx->br, &name, &nameLen)) || nameLen == 0) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: Invalid packet.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }

    // Get the new public key
    if (!br_read_blob(&commandCtx->br, P256_PUBLIC_KEY_SIZE, &publicKey)) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: Invalid packet.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }
    memcpy(publicKeyBuf, publicKey, P256_PUBLIC_KEY_SIZE);

    // Find the user
    targetUserId = userGetID(name, nameLen);
    if (targetUserId == 0) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: User not found.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_FOUND, "User not found", commandCtx->rxCounter, true);
    }

    // Check if the user is the same than us
    if (commandCtx->session->userId == targetUserId) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: Cannot reset own credentials.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Cannot reset own credentials", commandCtx->rxCounter, true);
    }

    // Check if the target user is an admin
    if (userIsAdmin(targetUserId, &targetIsAdmin) != ESP_OK || targetIsAdmin) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: Cannot reset user credentials.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Cannot reset user credentials", commandCtx->rxCounter, true);
    }

    // Change the user public key
    if (userChangeCredentials(targetUserId, commandCtx->session->userId, publicKeyBuf) != ESP_OK) {
        ESP_LOGD(TAG, "RESET USER PASSWORD command: Unable to reset user credentials.");
        return buildAndSendErrorReply(commandCtx, ESP_FAIL, "Unable to reset user credentials", commandCtx->rxCounter, true);
    }

    // Delete active target user sessions
    rwMutexLockRead(&commandCtx->serverCtx->sessions.mtx);
    for (SessionInfo_t *otherSession = commandCtx->serverCtx->sessions.first; otherSession; otherSession = otherSession->next) {
        // Dont close our own session
        if (otherSession->sockfd == commandCtx->sockfd) {
            continue;
        }

        if (otherSession->userId == targetUserId) {
            ESP_LOGD(TAG, "Closing session %u for deleted user %u", otherSession->id, otherSession->userId);
            otherSession->isClosed = true;
            closeWs(commandCtx->serverHandle, otherSession->sockfd, WS_CLOSE_GOING_AWAY, "User credentials has been reset");
        }
    }
    rwMutexUnlockRead(&commandCtx->serverCtx->sessions.mtx);

    // Done
    ESP_LOGD(TAG, "RESET USER PASSWORD command: User password successfully changed.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, commandCtx->rxCounter, true);
}

static esp_err_t handleChangeUserCredentials(CommandContext_t *commandCtx)
{
    const uint8_t *signature;
    const uint8_t *publicKey;
    uint8_t publicKeyBuf[P256_PUBLIC_KEY_SIZE];
    Sha256Context_t sha256Ctx;
    uint8_t th[SHA256_SIZE];
    uint8_t signatureToVerify[P256_SIGNATURE_SIZE];
    esp_err_t err;

    // Get the signature validation for the old key
    if (!br_read_blob(&commandCtx->br, P256_SIGNATURE_SIZE, &signature)) {
        ESP_LOGD(TAG, "CHANGE PASSWORD command: Invalid packet.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }

    // Get the new public key
    if (!br_read_blob(&commandCtx->br, P256_PUBLIC_KEY_SIZE, &publicKey)) {
        ESP_LOGD(TAG, "CHANGE PASSWORD command: Invalid packet.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }
    memcpy(publicKeyBuf, publicKey, P256_PUBLIC_KEY_SIZE);

    // th = SHA256("ws-chgcreds-v1" || publicKey || ws_nonce)
    sha256Init(&sha256Ctx);
    err = sha256Start(&sha256Ctx);
    if (err == ESP_OK) {
        err = sha256Update(&sha256Ctx, (const uint8_t *)"ws-chgcreds-v1", 14);
        if (err == ESP_OK) {
            err = sha256Update(&sha256Ctx, publicKeyBuf, P256_PUBLIC_KEY_SIZE);
            if (err == ESP_OK) {
                err = sha256Update(&sha256Ctx, commandCtx->session->nonce, sizeof(commandCtx->session->nonce));
                if (err == ESP_OK) {
                    err = sha256Finish(&sha256Ctx, th);
                }
            }
        }
    }
    sha256Done(&sha256Ctx);
    if (err != ESP_OK) {
error_validation_failed:
        ESP_LOGD(TAG, "CHANGE PASSWORD command: Validation failed.");
        if (commandCtx->session->credentialsChangeAttempts < 2) {
            commandCtx->session->credentialsChangeAttempts += 1;
            return buildAndSendErrorReply(commandCtx, ESP_FAIL, "Validation failed", commandCtx->rxCounter, true);
        }
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_POLICY_VIOLATION, nullptr);
    }

    // Validate old public key
    memcpy(signatureToVerify, signature, P256_SIGNATURE_SIZE);
    if (userVerifySignature(commandCtx->session->userId, th, signatureToVerify) != ESP_OK) {
        goto error_validation_failed;
    }

    // Reset change counter
    commandCtx->session->credentialsChangeAttempts = 0;

    // Change the user public key
    if (userChangeCredentials(commandCtx->session->userId, commandCtx->session->userId, publicKeyBuf) != ESP_OK) {
        ESP_LOGD(TAG, "CHANGE PASSWORD command: Unable to change user credentials.");
        return buildAndSendErrorReply(commandCtx, ESP_FAIL, "Unable to change user credentials", commandCtx->rxCounter, true);
    }

    commandCtx->session->mustChangeCredentials = 0;

    // Done
    ESP_LOGD(TAG, "CHANGE PASSWORD command: Credentials successfully changed.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, commandCtx->rxCounter, true);
}

static esp_err_t handleCustomCommand(CommandContext_t *commandCtx)
{
    IotCommCustomCommandEvent_t customCommandEvent;
    IotCommEvent_t event;
    OnTheFlyEvent_t otfe;

    // Setup on-the-fly event
    memset(&otfe, 0, sizeof(otfe));
    otfe.session = commandCtx->session;
    otfe.event = &event;
    otfe.commandCtx = commandCtx;

    // Populate event data
    memset(&event, 0, sizeof(event));
    event.sessionHandle = &otfe;
    event.eventType = IotCommEventTypeCustomCommand;
    event.ctx = handlerCtx;
    event.command = &customCommandEvent;
    customCommandEvent.cmd = commandCtx->cmd;
    customCommandEvent.data = commandCtx->br.ptr;
    customCommandEvent.dataLen = commandCtx->br.len;

    // Raise event
    handler(&event);

    // Handle actions in the event handler
    if (otfe.closeSent) {
        return otfe.closeErr;
    }
    if (otfe.replySent) {
        return otfe.savedErr;
    }

    // Done
    return ESP_OK;
}

static bool handleSessionStart(SessionInfo_t *session, httpd_req_t *req, esp_err_t *closeErr)
{
    IotCommEvent_t event;
    OnTheFlyEvent_t otfe;

    // Setup on-the-fly event
    memset(&otfe, 0, sizeof(otfe));
    otfe.session = session;
    otfe.req = req;
    otfe.event = &event;

    // Populate event data
    memset(&event, 0, sizeof(event));
    event.eventType = IotCommEventTypeSessionStart;
    event.sessionHandle = &otfe;
    event.ctx = handlerCtx;

    // Raise event
    handler(&event);

    // Done
    *closeErr = otfe.closeErr;
    return otfe.closeSent;
}

static void handleSessionEnd(SessionInfo_t *session)
{
    IotCommEvent_t event;
    OnTheFlyEvent_t otfe;

    // Setup on-the-fly event
    memset(&otfe, 0, sizeof(otfe));
    otfe.session = session;
    otfe.event = &event;

    // Populate event data'
    memset(&event, 0, sizeof(event));
    event.eventType = IotCommEventTypeSessionEnd;
    event.sessionHandle = &otfe;
    event.ctx = handlerCtx;

    // Raise event
    handler(&event);
}

static esp_err_t buildAndSendReply(CommandContext_t *commandCtx, const uint8_t *plaintextOut, size_t plaintextOutLen, uint32_t replyCounter,
                                   bool closeOnError)
{
    GrowableBuffer_t *ciphertextOut = &commandCtx->session->ciphertextOut;
    WebSocketPacketHeader_t *hdr;
    uint32_t nextTxCounter;
    httpd_ws_frame_t frame;
    uint8_t iv[SESSION_IV_LEN];
    size_t toSendSize;
    uint8_t *toSendPtr;
    httpd_ws_type_t toSendFrameType;
    esp_err_t err;

    // The plain text must not be empty
    if (plaintextOutLen == 0) {
        return ESP_FAIL;
    }

    // Prepare output for encrypted message
    gbReset(ciphertextOut, false);
    if (!gbEnsureSize(ciphertextOut, sizeof(WebSocketPacketHeader_t) + plaintextOutLen + TAG_LEN)) {
        err = ESP_ERR_NO_MEM;
on_error:
        return (closeOnError) ? closeWsWithCmdCtxAndError(commandCtx, "reply", err) : err;
    }

    // Header
    hdr = (WebSocketPacketHeader_t *)ciphertextOut->buffer;
    hdr->v = VERSION;
    be16enc(hdr->cmd, commandCtx->cmd);
    hdr->filler1 = 0;
    be32enc(hdr->replyCounter, replyCounter);
    be32enc(hdr->counter, commandCtx->session->nextTxCounter);
    hdr->filler2 = 0;

    // Build IV
    memcpy(iv, commandCtx->session->serverBaseIV, SESSION_IV_LEN);
    nextTxCounter = commandCtx->session->nextTxCounter;
    for (size_t i = 0; i < 4; i++) {
        iv[SESSION_IV_LEN-i-1] ^= (uint8_t)((nextTxCounter >> (i << 3)) & 0xFF);
    }

    // Encrypt message
    err = aesEncrypt(&commandCtx->session->serverAesCtx, plaintextOut, plaintextOutLen, iv, SESSION_IV_LEN,
                     nullptr, 0, ciphertextOut->buffer + sizeof(WebSocketPacketHeader_t));
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Unable to encrypt message. Error: %ld.", err);
        goto on_error;
    }

    // Send it
    toSendSize = sizeof(WebSocketPacketHeader_t) + plaintextOutLen + TAG_LEN;
    toSendPtr = ciphertextOut->buffer;
    toSendFrameType = HTTPD_WS_TYPE_BINARY;
    while (toSendSize > 0) {
        // Build frame
        memset(&frame, 0, sizeof(frame));
        frame.type = toSendFrameType;
        if (toSendSize <= MAX_OUTPUT_FRAME_SIZE) {
            frame.len = toSendSize;
            frame.final = false;
        }
        else {
            frame.len = MAX_OUTPUT_FRAME_SIZE;
            frame.final = true;
        }
        frame.payload = toSendPtr;

        toSendPtr += frame.len;
        toSendSize -= frame.len;
        toSendFrameType = HTTPD_WS_TYPE_CONTINUE;

        err = httpd_ws_send_frame_async(commandCtx->serverHandle, commandCtx->sockfd, &frame);
        if (err != ESP_OK) {
            ESP_LOGD(TAG, "Unable to deliver message. Error: %ld.", err);
            goto on_error;
        }
    }

    // Increment TX counter
    commandCtx->session->nextTxCounter += 1;

    // Done
    return ESP_OK;
}

static esp_err_t buildAndSendErrorReply(CommandContext_t *commandCtx, uint32_t code, const char *message, uint32_t replyCounter,
                                        bool closeOnError)
{
    uint8_t buf[4 + 128 + 1];
    size_t bufUsed;

    be32enc(buf, code);
    bufUsed = 4;

    if (message && *message != 0) {
        size_t msgLen = strlen(message);

        if (msgLen > 128) {
            msgLen = 128;
        }
        memcpy(buf + bufUsed, message, msgLen);
        bufUsed += msgLen;
    }

    // Send reply
    return buildAndSendReply(commandCtx, buf, bufUsed, replyCounter, closeOnError);
}

static esp_err_t closeWsWithCmdCtx(CommandContext_t *commandCtx, uint16_t code, const char *reason)
{
    commandCtx->session->isClosed = 1;
    return closeWs(commandCtx->serverHandle, commandCtx->sockfd, code, reason) ? ESP_OK : ESP_FAIL;
}

static esp_err_t closeWsWithCmdCtxAndError(CommandContext_t *commandCtx, const char *zone, esp_err_t err)
{
    char reason[64];

    snprintf(reason, sizeof(reason), "%s:%d", zone, err);
    return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INTERNAL_ERROR, reason);
}

static void destroyServerCtx(void *ctx)
{
    if (ctx) {
        ServerContext_t *serverCtx = (ServerContext_t *)ctx;

        rwMutexDeinit(&serverCtx->sessions.mtx);

        free(serverCtx);
    }
}

static void destroySessionCtx(void *ctx)
{
    if (ctx) {
        SessionInfo_t *session = (SessionInfo_t *)ctx;
        ServerContext_t *serverCtx = session->serverCtx;

        // Remove the session from the server's session list
        rwMutexLockWrite(&serverCtx->sessions.mtx);
        if (session->prev) {
            session->prev->next = session->next;
        }
        else {
            serverCtx->sessions.first = session->next;
        }
        if (session->next) {
            session->next->prev = session->prev;
        }
        else {
            serverCtx->sessions.last = session->prev;
        }
        rwMutexUnlockWrite(&serverCtx->sessions.mtx);

        // Call session end callback
        handleSessionEnd(session);

        destroySession(session);
    }
}

static SessionInfo_t *createSession()
{
    SessionInfo_t *session;

    // Create user session
    session = (SessionInfo_t *)malloc(sizeof(SessionInfo_t));
    if (!session) {
        return nullptr;
    }
    memset(session, 0, sizeof(SessionInfo_t));

    session->incomingMessageType = IncomingBufferTypeNone;
    session->plaintextIn = GB_STATIC_INIT;
    session->ciphertextIn = GB_STATIC_INIT;
    session->ciphertextOut = GB_STATIC_INIT;

    aesInit(&session->clientAesCtx);
    aesInit(&session->serverAesCtx);

    session->nextRxCounter = 1;
    session->nextTxCounter = 1;

    // Generate unique ID
    do {
        session->id = atomic_fetch_add_explicit(&nextSessionId, 1, memory_order_relaxed) & 0x7FFFFFFFUL;
    }
    while (session->id == 0);

    // Done
    return session;
}

static void destroySession(SessionInfo_t *session)
{
    if (session) {

        // Free user data
        if (session->userData) {
            if (session->userDataFreeFn) {
                session->userDataFreeFn(session->userData);
            }
            else {
                free(session->userData);
            }
        }

        aesDone(&session->clientAesCtx);
        aesDone(&session->serverAesCtx);

        gbWipe(&session->plaintextIn);
        gbReset(&session->plaintextIn, true);
        gbWipe(&session->ciphertextIn);
        gbReset(&session->ciphertextIn, true);
        gbWipe(&session->ciphertextOut);
        gbReset(&session->ciphertextOut, true);

        memset(session, 0, sizeof(SessionInfo_t));
        free(session);
    }
}

static esp_err_t readWsPacket(ServerContext_t *serverCtx, SessionInfo_t *session, httpd_req_t *req, bool *messageComplete)
{
    httpd_ws_frame_t frame;
    esp_err_t err;

    *messageComplete = false;

    // Read frame
    memset(&frame, 0, sizeof(frame));
    frame.type = HTTPD_WS_TYPE_TEXT;
    err = httpd_ws_recv_frame(req, &frame, 0);
    if (err != ESP_OK) {
        return err;
    }
    if (frame.len > 0) {
        if (frame.len > serverCtx->maxPacketSize - session->ciphertextIn.used) {
            return ESP_ERR_INVALID_SIZE;
        }
        frame.payload = (uint8_t *)gbReserve(&session->ciphertextIn, frame.len);
        if (!frame.payload) {
            return ESP_ERR_NO_MEM;
        }

        err = httpd_ws_recv_frame(req, &frame, frame.len);
        if (err != ESP_OK) {
            return err;
        }
    }

    switch (frame.type) {
        case HTTPD_WS_TYPE_TEXT:
            if (session->incomingMessageType != IncomingBufferTypeNone) {
                return ESP_ERR_INVALID_STATE;
            }
            session->incomingMessageType = IncomingBufferTypeText;
            break;

        case HTTPD_WS_TYPE_BINARY:
            if (session->incomingMessageType != IncomingBufferTypeNone) {
                return ESP_ERR_INVALID_STATE;
            }
            session->incomingMessageType = IncomingBufferTypeBinary;
            break;

        case HTTPD_WS_TYPE_CONTINUE:
            if (session->incomingMessageType == IncomingBufferTypeNone) {
                return ESP_ERR_INVALID_STATE;
            }
            break;

        default:
            return ESP_ERR_NOT_SUPPORTED;
    }

    // Check if final
    if (frame.final) {
        *messageComplete = true;
    }

    // Done
    return ESP_OK;
}

static bool closeWs(httpd_handle_t serverHandle, int sockfd, uint16_t code, const char *reason)
{
    httpd_ws_frame_t frame;
    uint8_t buf[256];

    memset(&frame, 0, sizeof(frame));
    frame.final = true;
    frame.type = HTTPD_WS_TYPE_CLOSE;
    frame.len = 2;
    frame.payload = buf;

    be16enc(buf, (code > 0) ? code : 1000);

    if (reason != nullptr && *reason != 0) {
        size_t msgLen = strlen(reason);
        if (msgLen > sizeof(buf) - 2) {
            msgLen = sizeof(buf) - 2;
        }
        memcpy(buf + 2, reason, msgLen);
        frame.len += msgLen;
    }

    return httpd_ws_send_frame_async(serverHandle, sockfd, &frame) == ESP_OK &&
           httpd_sess_trigger_close(serverHandle, sockfd) == ESP_OK;
}

static bool extGbAddB64(GrowableBuffer_t *buf, const uint8_t *src, size_t srcLen, bool isUrl)
{
    size_t maxLen, usedLen;
    char *b64Out;

    maxLen = B64_ENCODE_SIZE(srcLen) + 1;

    b64Out = (char *)gbReserve(buf, maxLen);
    if (!b64Out) {
        return false;
    }
    usedLen = maxLen;
    toB64(src, srcLen, isUrl, b64Out, &usedLen);
    if (maxLen > usedLen) {
        gbDel(buf, buf->used - (maxLen - usedLen), maxLen - usedLen);
    }
    return true;
}
