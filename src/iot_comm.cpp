#include "iot_comm/iot_comm.h"
#include "iot_comm/crypto/aes.h"
#include "iot_comm/crypto/hkdf.h"
#include "iot_comm/ota/ota.h"
#include "iot_comm/crypto/sha.h"
#include "iot_comm/crypto/utils.h"
#include "iot_comm/utils/binary.h"
#include "iot_comm/utils/network.h"
#include "challenge.h"
#include "device_identity.h"
#include "http_helpers.h"
#include "rate_limit.h"
#include "user.h"
#include <convert.h>
#include <cJSON.h>
#include <endian.h>
#include <esp_check.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <growable_buffer.h>
#include <mutex.h>
#include <rundown_protection.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/_types.h>
#include <task.h>

static const char* TAG = "IotComm";

#define VERSION 1

#define TAG_LEN     16
#define AES_KEY_LEN 32

#define SESSION_MASTER_INFO "mx-iot-session-master-v1"
#define AUTH_ENVELOPE_INFO  "mx-iot-auth-v1"
#define WS_TRANSPORT_INFO   "mx-iot-ws-v1"
#define UDP_TRANSPORT_INFO  "mx-iot-udp-v1"

#define AUTH_ENVELOPE_IV_LEN 12

#define MAX_BODY_SIZE 10240
#define MAX_QUERY_SIZE 1024

#define CMD_CREATE_USER             0x7FF1
#define CMD_DELETE_USER             0x7FF2
#define CMD_RESET_USER_CREDENTIALS  0x7FF3
#define CMD_CHANGE_USER_CREDENTIALS 0x7FF4
#define CMD_OTA_BEGIN               0x7FF5
#define CMD_OTA_WRITE               0x7FF6
#define CMD_OTA_CANCEL              0x7FF7
#define CMD_UDP_OPEN                0x7FF8

#define SESSION_FLAG_OTA_UPDATE     0x00000001UL

#define SESSION_IV_LEN     12
#define SESSION_AES_KEY_LEN    32

#define PACKET_FLAG_REPLY              0x01
#define PACKET_REPLY_COUNTER_LEN       8

#define MIN_WS_PACKET_SIZE 1024

#define MAX_OUTPUT_FRAME_SIZE 4096

#define GB_STR_AND_SIZE(str) (str), (sizeof(str) - 1)

// -----------------------------------------------------------------------------

typedef enum IncomingBufferType_e {
    IncomingBufferTypeNone = 0,
    IncomingBufferTypeBinary,
    IncomingBufferTypeText
} IncomingBufferType_t;

typedef struct ServerContext_s {
    size_t maxPacketSize;
    size_t maxConnectionsCount;
    uint16_t udpListenPort;

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
    uint64_t nextRxCounter;
    uint64_t nextTxCounter;
    ChallengeNonce_t nonce;
    ChallengeNonce_t clientUdpNonce;
    ChallengeNonce_t serverUdpNonce;
    uint32_t udpConnectionId;
    uint64_t udpNextRxCounter;
    uint8_t udpClientAesKey[AES_KEY_LEN];
    uint8_t udpClientBaseIV[SESSION_IV_LEN];
    uint8_t sessionMasterKey[SESSION_AES_KEY_LEN];
    AesContext_t clientAesCtx;
    uint8_t clientBaseIV[SESSION_IV_LEN];
    AesContext_t serverAesCtx;
    uint8_t serverBaseIV[SESSION_IV_LEN];
    uint8_t isAdmin : 1;
    uint8_t mustChangeCredentials : 1;
    uint8_t credentialsChangeAttempts : 2;
    uint8_t isClosed : 1;
    uint32_t refCount;
    uint32_t udpInFlight;
    uint32_t flags;
    SemaphoreHandle_t dispatchMtx;
    IncomingBufferType_t incomingMessageType;
    GrowableBuffer_t plaintextIn;
    GrowableBuffer_t ciphertextIn;
    GrowableBuffer_t ciphertextOut;
} SessionInfo_t;

// v(1) | cmd(2) | flags(1) | counter(8)
typedef struct __attribute__((packed)) PacketHeader_s {
    uint8_t v;
    uint8_t cmd[2];
    uint8_t flags;
    uint8_t counter[8];
} PacketHeader_t;

// udpConnectionId(4) | PacketHeader_t
typedef struct __attribute__((packed)) UdpPacketHeader_s {
    uint8_t        udpConnectionId[4];
    PacketHeader_t packetHeader;
} UdpPacketHeader_t;

static_assert(sizeof(PacketHeader_t) == 12, "Unexpected common packet header size.");
static_assert(sizeof(UdpPacketHeader_t) == 16, "Unexpected UDP packet header size.");

typedef struct CommandContext_s {
    httpd_handle_t serverHandle;
    int sockfd;
    ServerContext_t *serverCtx;
    SessionInfo_t *session;
    uint16_t cmd;
    binary_reader_t br;
    uint64_t rxCounter;
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

typedef struct ServeWsInitContext_s {
    IPAddress_t remoteAddr;
    GrowableBuffer_t reqBody;
    GrowableBuffer_t respBody;
    char *corsOrigin;
    cJSON *json;
    char *clientNonceValue;
    char *ecdhClientPublicKeyValue;
    size_t clientNonceLen;
    size_t ecdhClientPublicKeyLen;
    Challenge_t challenge;
    ChallengeCookie_t challengeCookie;
    P256KeyPair_t ecdhKeyPair;
    uint8_t devicePublicKey[P256_PUBLIC_KEY_SIZE];
    uint8_t deviceSignature[P256_SIGNATURE_SIZE];
    uint8_t transcriptHash[SHA256_SIZE];
} ServeWsInitContext_t;

typedef struct ServeWsAuthContext_s {
    IPAddress_t remoteAddr;
    GrowableBuffer_t reqBody;
    GrowableBuffer_t respBody;
    GrowableBuffer_t plaintextBody;
    char *corsOrigin;
    bool removeChallenge;
    cJSON *json;
    cJSON *innerJson;
    char *cookieValue;
    char *authIvValue;
    char *encryptedAuthValue;
    char *userNameValue;
    char *authNonceValue;
    char *signatureValue;
    ChallengeCookie_t challengeCookie;
    uint8_t authIv[AUTH_ENVELOPE_IV_LEN];
    uint8_t authKey[AES_KEY_LEN];
    uint8_t sharedSecret[P256_SHARED_SECRET_SIZE];
    uint8_t sessionSalt[SHA256_SIZE];
    uint8_t authNonce[CHALLENGE_NONCE_SIZE];
    uint8_t signature[P256_SIGNATURE_SIZE];
    size_t challengeCookieLen;
    size_t authIvLen;
    size_t authNonceLen;
    size_t signatureLen;
    size_t encryptedAuthLen;
    Challenge_t *challenge;
    P256KeyPair_t ecdhKeyPair;
    AesContext_t aesCtx;
    uint8_t *encryptedAuth;
    char *plaintext;
    size_t plaintextLen;
    uint8_t th[SHA256_SIZE];
    bool b;
} ServeWsAuthContext_t;

typedef struct ServeWsPreHandshakeContext_s {
    ServerContext_t *serverCtx;
    IPAddress_t remoteAddr;
    GrowableBuffer_t reqQueryParams;
    char ticketB64[B64_ENCODE_SIZE(CHALLENGE_WS_TICKET_SIZE) + 1];
    ChallengeWsTicket_t wsTicket;
    bool removeChallenge;
    bool carrierSelected;
    size_t wsTicketLen;
    Challenge_t *challenge;
    Challenge_t challengeCopy;
    P256KeyPair_t ecdhKeyPair;
    uint8_t salt[SHA256_SIZE];
    uint8_t sharedSecret[P256_SHARED_SECRET_SIZE];
    uint8_t sessionMasterKey[SESSION_AES_KEY_LEN];
    uint8_t derivedKey[2 * AES_KEY_LEN + 2 * SESSION_IV_LEN];
    SessionInfo_t *session;
    bool b;
} ServeWsPreHandshakeContext_t;

// -----------------------------------------------------------------------------

static RWMutex rwNtx;
static RundownProtection_t rp = RUNDOWN_PROTECTION_INIT_STATIC;
static IotCommEventHandler_t handler = nullptr;
static void *handlerCtx = nullptr;
static httpd_handle_t server = nullptr;
static ServerContext_t *activeServerCtx = nullptr;
static _Atomic(uint32_t) nextSessionId = {0};
static Task_t otaRestartTask = TASK_INIT_STATIC;
static Task_t udpServerTask = TASK_INIT_STATIC;
static int udpServerSocket = -1;

// -----------------------------------------------------------------------------

static void iotCommDeinitNoLock();
static void iotCommStopServerNoLock();

static esp_err_t serveWsInit(httpd_req_t *req);
static esp_err_t serveWsAuth(httpd_req_t *req);
static esp_err_t serveWsPreHandshake(httpd_req_t *req);
static esp_err_t serveWs(httpd_req_t *req);
static esp_err_t serveWsPacket(httpd_req_t *req);
static esp_err_t dispatchCommand(CommandContext_t *commandCtx);

static esp_err_t handleCreateUser(CommandContext_t *commandCtx);
static esp_err_t handleDeleteUser(CommandContext_t *commandCtx);
static esp_err_t handleResetUserCredentials(CommandContext_t *commandCtx);
static esp_err_t handleChangeUserCredentials(CommandContext_t *commandCtx);
static esp_err_t handleOtaBegin(CommandContext_t *commandCtx);
static esp_err_t handleOtaWrite(CommandContext_t *commandCtx);
static esp_err_t handleOtaCancel(CommandContext_t *commandCtx);
static esp_err_t handleUdpOpen(CommandContext_t *commandCtx);
static esp_err_t handleCustomCommand(CommandContext_t *commandCtx);

static bool handleSessionStart(SessionInfo_t *session, httpd_req_t *req, esp_err_t *closeErr);
static void handleSessionEnd(SessionInfo_t *session);

static esp_err_t buildAndSendReply(CommandContext_t *commandCtx, const uint8_t *plaintextOut, size_t plaintextOutLen, bool closeOnError);
static esp_err_t buildAndSendErrorReply(CommandContext_t *commandCtx, uint32_t code, const char *message, bool closeOnError);

static esp_err_t encryptAndSend(SessionInfo_t *session, httpd_handle_t serverHandle, uint16_t cmd, const uint8_t *plaintextOut,
                                size_t plaintextOutLen, const uint64_t *replyCounter, bool closeOnError);

static esp_err_t closeWsWithSession(SessionInfo_t *session, httpd_handle_t serverHandle, uint16_t code, const char *reason);
static esp_err_t closeWsWithSessionAndError(SessionInfo_t *session, httpd_handle_t serverHandle, const char *zone, esp_err_t err);
static esp_err_t closeWsWithCmdCtx(CommandContext_t *commandCtx, uint16_t code, const char *reason);
static esp_err_t closeWsWithCmdCtxAndError(CommandContext_t *commandCtx, const char *zone, esp_err_t err);

static void destroyServerCtx(void *ctx);
static void destroySessionCtx(void *ctx);

static SessionInfo_t *createSession();
static void incrementSessionRefCount(SessionInfo_t *session);
static void decrementSessionRefCount(SessionInfo_t *session);
static void freeSession(SessionInfo_t *session);

static esp_err_t readWsPacket(ServerContext_t *serverCtx, SessionInfo_t *session, httpd_req_t *req, bool *messageComplete);

static bool closeWs(httpd_handle_t serverHandle, int sockfd, uint16_t code, const char *reason);
static void otaRestartTaskMain(Task_t *task, void *arg);

static esp_err_t startUdpServer(ServerContext_t *serverCtx);
static void stopUdpServer();
static void udpServerTaskMain(Task_t *task, void *arg);
static void processUdpPacket(ServerContext_t *serverCtx, const uint8_t *packet, size_t packetLen, const IPAddress_t *remoteAddr);

static bool extGbAddB64(GrowableBuffer_t *buf, const uint8_t *src, size_t srcLen, bool isUrl);
static bool extGbAddBool(GrowableBuffer_t *buf, bool value);
static bool extGbAddSizeT(GrowableBuffer_t *buf, size_t value);

static esp_err_t sha256Build(uint8_t hash[SHA256_SIZE], const uint8_t *const *parts, const size_t *partLens, size_t partsCount);

static esp_err_t buildWsServerAuthHash(const Challenge_t *challenge, uint8_t hash[SHA256_SIZE]);
static esp_err_t buildWsUserAuthHash(const Challenge_t *challenge, const uint8_t authNonce[CHALLENGE_NONCE_SIZE], const char *userName,
                                     size_t userNameLen, uint8_t hash[SHA256_SIZE]);

static esp_err_t deriveWsLoginSalt(const Challenge_t *challenge, const uint8_t *extra, size_t extraLen, uint8_t salt[SHA256_SIZE]);
static esp_err_t deriveSessionMasterKey(const uint8_t sharedSecret[P256_SHARED_SECRET_SIZE], const uint8_t *salt, size_t saltLen,
                                        uint8_t sessionMasterKey[SESSION_AES_KEY_LEN]);
static esp_err_t deriveAuthEnvelopeKey(const uint8_t sharedSecret[P256_SHARED_SECRET_SIZE], const uint8_t salt[SHA256_SIZE],
                                       uint8_t authKey[AES_KEY_LEN]);
static esp_err_t deriveTransportKeys(const uint8_t sessionMasterKey[SESSION_AES_KEY_LEN], const uint8_t *salt, size_t saltLen,
                                     const uint8_t *info, size_t infoLen,
                                     uint8_t derivedKey[2 * AES_KEY_LEN + 2 * SESSION_IV_LEN]);

static esp_err_t sendCORSPreflightResponse(httpd_req_t *req);

static bool tryExtractWsTicketFromQuery(const char *query, char *ticketB64, size_t ticketB64Len, bool *selected);
static bool tryExtractWsTicketFromAuthorization(httpd_req_t *req, char *ticketB64, size_t ticketB64Len, bool *selected);

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
    ESP_GOTO_ON_ERROR(usersInit(&usersConfig), on_error, TAG, "Failed to initialize the user manager");
    ESP_GOTO_ON_ERROR(deviceIdentityInit(&config->storage), on_error, TAG, "Failed to initialize the device identity");

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
                      on_error, TAG, "Failed to initialize the rate-limit handler");

    ESP_GOTO_ON_ERROR(challengesInit(config->challenge.maxSlots, config->challenge.windowSizeInMs), on_error, TAG,
                      "Failed to initialize the challenge manager");

    // Save event handler
    handler = config->handler;
    handlerCtx = config->handlerCtx;

    // Done
    ESP_LOGI(TAG, "Initialized.");
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
    serverCtx->udpListenPort = config->udpListenPort;
    rwMutexInit(&serverCtx->sessions.mtx);

    // Setup http server configuration
    httpdConfig = HTTPD_DEFAULT_CONFIG();
    httpdConfig.server_port = config->listenPort;
    httpdConfig.max_open_sockets = config->maxConnections;
    httpdConfig.core_id = tskNO_AFFINITY;
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
    activeServerCtx = serverCtx;

    if (serverCtx->udpListenPort != 0) {
        err = startUdpServer(serverCtx);
        if (err != ESP_OK) {
            goto on_error;
        }
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
    uri.ws_pre_handshake_cb = serveWsPreHandshake;
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
    ESP_LOGI(TAG, "Server initialized and listening on port %u.", config->listenPort);
    return ESP_OK;

on_error:
    ESP_LOGE(TAG, "Failed to start the HTTP server. Error: %d.", err);
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

esp_err_t iotCommEventReply(IotCommSessionHandle_t h, const uint8_t *reply, size_t replyLen)
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
        otfe->savedErr = buildAndSendReply(otfe->commandCtx, reply, replyLen, false);
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
        otfe->savedErr = buildAndSendErrorReply(otfe->commandCtx, code, message, false);
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

esp_err_t iotCommGetDeviceIdentityPublicKey(uint8_t publicKey[P256_PUBLIC_KEY_SIZE])
{
    AutoRWMutex lock(rwNtx, false);

    if (!publicKey) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!handler) {
        return ESP_ERR_INVALID_STATE;
    }

    return deviceIdentityGetPublicKey(publicKey);
}

// -----------------------------------------------------------------------------

static void iotCommDeinitNoLock()
{
    iotCommStopServerNoLock();

    challengesDeinit();
    rateLimitDeinit();
    deviceIdentityDeinit();
    usersDeinit();

    handler = nullptr;
    handlerCtx = nullptr;
}

static void iotCommStopServerNoLock()
{
    stopUdpServer();

    if (server) {
        httpd_stop(server);
        server = nullptr;
    }
}

static esp_err_t serveWsInit(httpd_req_t *req)
{
    AutoRundownProtection rpLock(rp);
    esp_err_t err;
    ServeWsInitContext_t *ctx;
    ServerContext_t *serverCtx;

    if (!rpLock.acquired()) {
        return ESP_ERR_INVALID_STATE;
    }

    serverCtx = (ServerContext_t *)httpd_get_global_user_ctx(req->handle);
    if (!serverCtx) {
        return ESP_ERR_INVALID_STATE;
    }

    if (req->method == HTTP_OPTIONS) {
        return sendCORSPreflightResponse(req);
    }

    ctx = (ServeWsInitContext_t *)malloc(sizeof(ServeWsInitContext_t));
    if (!ctx) {
        return ESP_ERR_NO_MEM;
    }
    memset(ctx, 0, sizeof(ServeWsInitContext_t));
    ctx->reqBody = GB_STATIC_INIT;
    ctx->respBody = GB_STATIC_INIT;
    p256KeyPairInit(&ctx->ecdhKeyPair);

    err = httpGetCORSOrigin(req, &ctx->corsOrigin);
    if (err == ESP_OK) {
        err = httpSendDefaultCORS(req, ctx->corsOrigin);
    }
    if (err != ESP_OK) {
        goto done;
    }

    if (!httpGetClientIpFromRequest(req, &ctx->remoteAddr)) {
        ESP_LOGE(TAG, "Failed to determine the client's IP address.");
        err = ESP_FAIL;
        goto done;
    }

    if (rateLimitIsAddressBlocked(&ctx->remoteAddr)) {
        err = httpd_resp_send_custom_err(req, "429 Too Many Requests", "");
        goto done;
    }

    if (!rateLimitCheckRequest(&ctx->remoteAddr)) {
        err = httpd_resp_send_custom_err(req, "429 Too Many Requests", "");
        goto done;
    }

    if (req->content_len > MAX_BODY_SIZE) {
        err = httpd_resp_send_err(req, HTTPD_413_CONTENT_TOO_LARGE, nullptr);
        goto done;
    }
    err = httpGetRequestBody(&ctx->reqBody, req);
    if (err != ESP_OK) {
        goto done;
    }

    ctx->json = cJSON_ParseWithLength((const char*)ctx->reqBody.buffer, ctx->reqBody.used);
    if (!(ctx->json && cJSON_IsObject(ctx->json))) {
error_invalid_data:
        err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid parameters");
        goto done;
    }

    ctx->clientNonceValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(ctx->json, "clientNonce"));
    ctx->ecdhClientPublicKeyValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(ctx->json, "clientPublicKey"));
    if ((!ctx->clientNonceValue) || (!ctx->ecdhClientPublicKeyValue)) {
        goto error_invalid_data;
    }

    ctx->clientNonceLen = sizeof(ctx->challenge.clientNonce);
    ctx->ecdhClientPublicKeyLen = sizeof(ctx->challenge.ecdhClientPublicKey);
    if (
        (!fromB64(ctx->clientNonceValue, strlen(ctx->clientNonceValue), false, ctx->challenge.clientNonce, &ctx->clientNonceLen)) ||
        (!fromB64(ctx->ecdhClientPublicKeyValue, strlen(ctx->ecdhClientPublicKeyValue), false, ctx->challenge.ecdhClientPublicKey,
                  &ctx->ecdhClientPublicKeyLen))
    ) {
        goto error_invalid_data;
    }
    if (
        ctx->clientNonceLen != CHALLENGE_NONCE_SIZE || ctx->ecdhClientPublicKeyLen != P256_PUBLIC_KEY_SIZE ||
        (!p256ValidatePublicKey(ctx->challenge.ecdhClientPublicKey, P256_PUBLIC_KEY_SIZE))
    ) {
        goto error_invalid_data;
    }

    if (
        randomize(ctx->challenge.serverNonce, sizeof(ctx->challenge.serverNonce)) != ESP_OK ||
        randomize(ctx->challengeCookie, sizeof(ctx->challengeCookie)) != ESP_OK ||
        ecdhGeneratePair(&ctx->ecdhKeyPair) != ESP_OK ||
        p256SavePublicKey(&ctx->ecdhKeyPair, ctx->challenge.ecdhServerPublicKey) != ESP_OK ||
        p256SavePrivateKey(&ctx->ecdhKeyPair, ctx->challenge.ecdhServerPrivateKey) != ESP_OK
    ) {
        err = ESP_FAIL;
        goto done;
    }

    memcpy(ctx->challenge.token, ctx->challengeCookie, sizeof(ctx->challenge.token));

    err = buildWsServerAuthHash(&ctx->challenge, ctx->transcriptHash);
    if (err == ESP_OK) {
        err = deviceIdentityGetPublicKey(ctx->devicePublicKey);
    }
    if (err == ESP_OK) {
        err = deviceIdentitySignHash(ctx->transcriptHash, ctx->deviceSignature);
    }
    if (err != ESP_OK) {
        goto done;
    }

    challengesAdd(ctx->challengeCookie, &ctx->remoteAddr, &ctx->challenge);

    if (
        (!gbAdd(&ctx->respBody, GB_STR_AND_SIZE("{\"token\":\""))) ||
        (!extGbAddB64(&ctx->respBody, ctx->challengeCookie, sizeof(ctx->challengeCookie), false)) ||
        (!gbAdd(&ctx->respBody, GB_STR_AND_SIZE("\",\"serverNonce\":\""))) ||
        (!extGbAddB64(&ctx->respBody, ctx->challenge.serverNonce, sizeof(ctx->challenge.serverNonce), false)) ||
        (!gbAdd(&ctx->respBody, GB_STR_AND_SIZE("\",\"serverPublicKey\":\""))) ||
        (!extGbAddB64(&ctx->respBody, ctx->challenge.ecdhServerPublicKey, sizeof(ctx->challenge.ecdhServerPublicKey), false)) ||
        (!gbAdd(&ctx->respBody, GB_STR_AND_SIZE("\",\"devicePublicKey\":\""))) ||
        (!extGbAddB64(&ctx->respBody, ctx->devicePublicKey, sizeof(ctx->devicePublicKey), false)) ||
        (!gbAdd(&ctx->respBody, GB_STR_AND_SIZE("\",\"deviceSignature\":\""))) ||
        (!extGbAddB64(&ctx->respBody, ctx->deviceSignature, sizeof(ctx->deviceSignature), false)) ||
        (!gbAdd(&ctx->respBody, GB_STR_AND_SIZE("\",\"maxPacketSize\":"))) ||
        (!extGbAddSizeT(&ctx->respBody, serverCtx->maxPacketSize)) ||
        (!gbAdd(&ctx->respBody, GB_STR_AND_SIZE("}")))
    ) {
        err = ESP_ERR_NO_MEM;
        goto done;
    }

    err = httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        err = httpd_resp_send(req, (char *)ctx->respBody.buffer, (ssize_t)ctx->respBody.used);
    }

done:
    err = httpSendInternalErrorResponse(req, err, nullptr);

    // Cleanup
    if (ctx->json) {
        cJSON_Delete(ctx->json);
    }
    p256KeyPairDone(&ctx->ecdhKeyPair);
    gbWipe(&ctx->respBody);
    gbReset(&ctx->respBody, true);
    gbWipe(&ctx->reqBody);
    gbReset(&ctx->reqBody, true);
    httpFreeCORSOrigin(ctx->corsOrigin);
    memset(ctx, 0, sizeof(ServeWsInitContext_t));
    free(ctx);

    // Done
    return err;
}

static esp_err_t serveWsAuth(httpd_req_t *req)
{
    AutoRundownProtection rpLock(rp);
    ServeWsAuthContext_t *ctx;
    esp_err_t err;

    if (!rpLock.acquired()) {
        return ESP_ERR_INVALID_STATE;
    }

    if (req->method == HTTP_OPTIONS) {
        return sendCORSPreflightResponse(req);
    }

    ctx = (ServeWsAuthContext_t *)malloc(sizeof(ServeWsAuthContext_t));
    if (!ctx) {
        return ESP_ERR_NO_MEM;
    }
    memset(ctx, 0, sizeof(ServeWsAuthContext_t));
    ctx->reqBody = GB_STATIC_INIT;
    ctx->respBody = GB_STATIC_INIT;
    ctx->plaintextBody = GB_STATIC_INIT;
    p256KeyPairInit(&ctx->ecdhKeyPair);
    aesInit(&ctx->aesCtx);

    err = httpGetCORSOrigin(req, &ctx->corsOrigin);
    if (err == ESP_OK) {
        err = httpSendDefaultCORS(req, ctx->corsOrigin);
    }
    if (err != ESP_OK) {
        goto done;
    }

    if (!httpGetClientIpFromRequest(req, &ctx->remoteAddr)) {
        ESP_LOGE(TAG, "Failed to determine the client's IP address.");
        err = ESP_FAIL;
        goto done;
    }

    if (rateLimitIsAddressBlocked(&ctx->remoteAddr)) {
        err = httpd_resp_send_custom_err(req, "429 Too Many Requests", "");
        goto done;
    }

    if (!rateLimitCheckRequest(&ctx->remoteAddr)) {
        err = httpd_resp_send_custom_err(req, "429 Too Many Requests", "");
        goto done;
    }

    if (req->content_len > MAX_BODY_SIZE) {
        err = httpd_resp_send_err(req, HTTPD_413_CONTENT_TOO_LARGE, nullptr);
        goto done;
    }
    err = httpGetRequestBody(&ctx->reqBody, req);
    if (err != ESP_OK) {
        goto done;
    }

    ctx->json = cJSON_ParseWithLength((const char*)ctx->reqBody.buffer, ctx->reqBody.used);
    if (!(ctx->json && cJSON_IsObject(ctx->json))) {
error_invalid_data:
        err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid parameters");
        goto done;
    }

    ctx->cookieValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(ctx->json, "token"));
    ctx->authIvValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(ctx->json, "authIv"));
    ctx->encryptedAuthValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(ctx->json, "encryptedAuth"));
    if ((!ctx->cookieValue) || (!ctx->authIvValue) || (!ctx->encryptedAuthValue)) {
        goto error_invalid_data;
    }

    ctx->challengeCookieLen = sizeof(ctx->challengeCookie);
    ctx->authIvLen = sizeof(ctx->authIv);
    ctx->encryptedAuthLen = B64_ENCODE_SIZE(strlen(ctx->encryptedAuthValue));
    ctx->encryptedAuth = (uint8_t *)malloc(ctx->encryptedAuthLen);
    if (!ctx->encryptedAuth) {
        err = ESP_ERR_NO_MEM;
        goto done;
    }
    if (
        (!fromB64(ctx->cookieValue, strlen(ctx->cookieValue), false, ctx->challengeCookie, &ctx->challengeCookieLen)) ||
        (!fromB64(ctx->authIvValue, strlen(ctx->authIvValue), false, ctx->authIv, &ctx->authIvLen)) ||
        (!fromB64(ctx->encryptedAuthValue, strlen(ctx->encryptedAuthValue), false, ctx->encryptedAuth, &ctx->encryptedAuthLen))
    ) {
        goto error_invalid_data;
    }
    if (ctx->challengeCookieLen != CHALLENGE_COOKIE_SIZE || ctx->authIvLen != AUTH_ENVELOPE_IV_LEN || ctx->encryptedAuthLen < 2 + TAG_LEN) {
        // We expect at least 2 bytes of plaintext because a JSON object must be at least 2 bytes (e.g., "{}").
        goto error_invalid_data;
    }

    ctx->challenge = challengesFindByToken(ctx->challengeCookie, &ctx->remoteAddr);
    if (!ctx->challenge) {
error_not_auth:
        err = httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, nullptr);
        goto done;
    }
    ctx->removeChallenge = true;

    err = deriveWsLoginSalt(ctx->challenge, nullptr, 0, ctx->sessionSalt);
    if (err == ESP_OK) {
        err = p256LoadPrivateKey(&ctx->ecdhKeyPair, ctx->challenge->ecdhServerPrivateKey);
    }
    if (err == ESP_OK) {
        err = p256LoadPublicKey(&ctx->ecdhKeyPair, ctx->challenge->ecdhClientPublicKey);
    }
    if (err == ESP_OK) {
        err = ecdhComputeSharedSecret(&ctx->ecdhKeyPair, ctx->sharedSecret);
    }
    if (err == ESP_OK) {
        err = deriveAuthEnvelopeKey(ctx->sharedSecret, ctx->sessionSalt, ctx->authKey);
    }
    if (err == ESP_OK) {
        err = aesSetKey(&ctx->aesCtx, ctx->authKey, sizeof(ctx->authKey));
    }
    if (err != ESP_OK) {
        goto done;
    }

    ctx->plaintextLen = ctx->encryptedAuthLen - TAG_LEN;
    ctx->plaintext = (char *)gbReserve(&ctx->plaintextBody, ctx->plaintextLen);
    if (!ctx->plaintext) {
        err = ESP_ERR_NO_MEM;
        goto done;
    }

    err = aesDecrypt(&ctx->aesCtx, ctx->encryptedAuth, ctx->encryptedAuthLen, ctx->authIv, sizeof(ctx->authIv), nullptr, 0,
                     (uint8_t *)ctx->plaintext);
    if (err != ESP_OK) {
        rateLimitIncrementFailedAuth(&ctx->remoteAddr);
        goto error_not_auth;
    }
    ctx->plaintextBody.used = ctx->plaintextLen;

    ctx->innerJson = cJSON_ParseWithLength((const char *)ctx->plaintextBody.buffer, ctx->plaintextBody.used);
    if (!(ctx->innerJson && cJSON_IsObject(ctx->innerJson))) {
        goto error_invalid_data;
    }

    ctx->userNameValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(ctx->innerJson, "userName"));
    ctx->authNonceValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(ctx->innerJson, "authNonce"));
    ctx->signatureValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(ctx->innerJson, "signature"));
    if ((!ctx->userNameValue) || *ctx->userNameValue == 0 || (!ctx->authNonceValue) || (!ctx->signatureValue)) {
        goto error_invalid_data;
    }

    ctx->authNonceLen = sizeof(ctx->authNonce);
    ctx->signatureLen = sizeof(ctx->signature);
    if (
        (!fromB64(ctx->authNonceValue, strlen(ctx->authNonceValue), false, ctx->authNonce, &ctx->authNonceLen)) ||
        (!fromB64(ctx->signatureValue, strlen(ctx->signatureValue), false, ctx->signature, &ctx->signatureLen))
    ) {
        goto error_invalid_data;
    }
    if (ctx->authNonceLen != CHALLENGE_NONCE_SIZE || ctx->signatureLen != P256_SIGNATURE_SIZE) {
        goto error_invalid_data;
    }

    ctx->challenge->userId = userGetID(ctx->userNameValue, strlen(ctx->userNameValue));
    if (ctx->challenge->userId == 0) {
        rateLimitIncrementFailedAuth(&ctx->remoteAddr);
        goto error_not_auth;
    }

    err = buildWsUserAuthHash(ctx->challenge, ctx->authNonce, ctx->userNameValue, strlen(ctx->userNameValue), ctx->th);
    if (err != ESP_OK) {
        goto done;
    }

    err = userVerifySignature(ctx->challenge->userId, ctx->th, ctx->signature);
    if (err != ESP_OK) {
        rateLimitIncrementFailedAuth(&ctx->remoteAddr);
        if (err == ESP_ERR_NOT_FOUND || err == ESP_ERR_SIGNATURE_VERIFICATION_FAILED || err == ESP_ERR_INVALID_STATE) {
            challengesRemove(ctx->challengeCookie);
            goto error_not_auth;
        }
        goto done;
    }

    ctx->challenge->verified = true;

    err = randomize(ctx->challenge->wsNonce, sizeof(ctx->challenge->wsNonce));
    if (err == ESP_OK) {
        err = randomize(ctx->challenge->wsTicket, sizeof(ctx->challenge->wsTicket));
    }
    if (err != ESP_OK) {
        goto done;
    }

    err = userMustChangeCredentials(ctx->challenge->userId, &ctx->b);
    if (err != ESP_OK) {
        goto done;
    }
    if (!(gbAdd(&ctx->respBody, GB_STR_AND_SIZE("{\"mustChangeCredentials\":")) && extGbAddBool(&ctx->respBody, ctx->b))) {
error_no_mem:
        err = ESP_ERR_NO_MEM;
        goto done;
    }

    err = userIsAdmin(ctx->challenge->userId, &ctx->b);
    if (err != ESP_OK) {
        goto done;
    }
    if (!(gbAdd(&ctx->respBody, GB_STR_AND_SIZE(",\"isAdmin\":")) && extGbAddBool(&ctx->respBody, ctx->b))) {
        goto error_no_mem;
    }

    if (
        (!gbAdd(&ctx->respBody, GB_STR_AND_SIZE(",\"wsNonce\":\""))) ||
        (!extGbAddB64(&ctx->respBody, ctx->challenge->wsNonce, sizeof(ctx->challenge->wsNonce), false)) ||
        (!gbAdd(&ctx->respBody, GB_STR_AND_SIZE("\",\"wsTicket\":\""))) ||
        (!extGbAddB64(&ctx->respBody, ctx->challenge->wsTicket, sizeof(ctx->challenge->wsTicket), true)) ||
        (!gbAdd(&ctx->respBody, GB_STR_AND_SIZE("\"}")))
    ) {
        goto error_no_mem;
    }

    err = httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        err = httpd_resp_send(req, (char *)ctx->respBody.buffer, (ssize_t)ctx->respBody.used);
    }

    ctx->removeChallenge = false;

done:
    if (ctx->removeChallenge) {
        challengesRemove(ctx->challengeCookie);
    }

    err = httpSendInternalErrorResponse(req, err, nullptr);

    // Cleanup
    if (ctx->json) {
        cJSON_Delete(ctx->json);
    }
    if (ctx->innerJson) {
        cJSON_Delete(ctx->innerJson);
    }
    if (ctx->encryptedAuth) {
        memset(ctx->encryptedAuth, 0, ctx->encryptedAuthLen);
        free(ctx->encryptedAuth);
    }
    p256KeyPairDone(&ctx->ecdhKeyPair);
    aesDone(&ctx->aesCtx);
    gbWipe(&ctx->respBody);
    gbReset(&ctx->respBody, true);
    gbWipe(&ctx->plaintextBody);
    gbReset(&ctx->plaintextBody, true);
    gbWipe(&ctx->reqBody);
    gbReset(&ctx->reqBody, true);
    httpFreeCORSOrigin(ctx->corsOrigin);
    memset(ctx, 0, sizeof(ServeWsAuthContext_t));
    free(ctx);

    // Done
    return err;
}

static esp_err_t serveWsPreHandshake(httpd_req_t *req)
{
    AutoRundownProtection rpLock(rp);
    ServeWsPreHandshakeContext_t *ctx;
    bool success = false;
    esp_err_t err;

    if (!rpLock.acquired()) {
        return ESP_ERR_INVALID_STATE;
    }

    ctx = (ServeWsPreHandshakeContext_t *)malloc(sizeof(ServeWsPreHandshakeContext_t));
    if (!ctx) {
        return ESP_ERR_NO_MEM;
    }
    memset(ctx, 0, sizeof(ServeWsPreHandshakeContext_t));
    ctx->serverCtx = (ServerContext_t *)httpd_get_global_user_ctx(req->handle);
    ctx->reqQueryParams = GB_STATIC_INIT;
    p256KeyPairInit(&ctx->ecdhKeyPair);

    // Prepare
    // Get request IP address
    if (!httpGetClientIpFromRequest(req, &ctx->remoteAddr)) {
        ESP_LOGE(TAG, "Failed to determine the client's IP address.");
        err = ESP_FAIL;
        goto done;
    }

    if (rateLimitIsAddressBlocked(&ctx->remoteAddr)) {
        err = httpd_resp_send_custom_err(req, "429 Too Many Requests", "");
        goto done;
    }

    // Check rate limit
    if (!rateLimitCheckRequest(&ctx->remoteAddr)) {
        err = httpd_resp_send_custom_err(req, "429 Too Many Requests", "");
        goto done;
    }

    // Read request quey
    err = httpGetRequestQueryParams(&ctx->reqQueryParams, req, MAX_QUERY_SIZE);
    if (err != ESP_OK) {
        if (err == ESP_ERR_INVALID_SIZE) {
            err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Query too long");
        }
        goto done;
    }

    // Extract selected carrier in precedence order: query, Authorization header.
    if (
        !tryExtractWsTicketFromQuery((const char *)ctx->reqQueryParams.buffer, ctx->ticketB64, sizeof(ctx->ticketB64), &ctx->carrierSelected) ||
        (!ctx->carrierSelected && !tryExtractWsTicketFromAuthorization(req, ctx->ticketB64, sizeof(ctx->ticketB64), &ctx->carrierSelected))
    ) {
error_invalid_data:
        err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid parameters");
        goto done;
    }
    if (!ctx->carrierSelected) {
error_not_auth:
        err = httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, nullptr);
        goto done;
    }

    ctx->wsTicketLen = sizeof(ctx->wsTicket);
    if ((!fromB64(ctx->ticketB64, strlen(ctx->ticketB64), true, ctx->wsTicket, &ctx->wsTicketLen)) ||
        ctx->wsTicketLen != CHALLENGE_WS_TICKET_SIZE) {
        goto error_invalid_data;
    }

    ctx->challenge = challengesFindByWsTicket(ctx->wsTicket, &ctx->remoteAddr);
    if (!ctx->challenge) {
        goto error_not_auth;
    }
    memcpy(&ctx->challengeCopy, ctx->challenge, sizeof(ctx->challengeCopy));
    ctx->removeChallenge = true;

    err = deriveWsLoginSalt(&ctx->challengeCopy, nullptr, 0, ctx->salt);
    if (err != ESP_OK) {
        goto done;
    }

    // Compute shared secret and derive keys
    err = p256LoadPrivateKey(&ctx->ecdhKeyPair, ctx->challengeCopy.ecdhServerPrivateKey);
    if (err == ESP_OK) {
        err = p256LoadPublicKey(&ctx->ecdhKeyPair, ctx->challengeCopy.ecdhClientPublicKey);
        if (err == ESP_OK) {
            err = ecdhComputeSharedSecret(&ctx->ecdhKeyPair, ctx->sharedSecret);
        }
    }
    if (err != ESP_OK) {
        goto done;
    }
    err = deriveSessionMasterKey(ctx->sharedSecret, ctx->salt, sizeof(ctx->salt), ctx->sessionMasterKey);
    if (err != ESP_OK) {
        goto done;
    }

    err = deriveWsLoginSalt(&ctx->challengeCopy, ctx->challengeCopy.wsNonce, sizeof(ctx->challengeCopy.wsNonce), ctx->salt);
    if (err != ESP_OK) {
        goto done;
    }

    err = deriveTransportKeys(ctx->sessionMasterKey, ctx->salt, sizeof(ctx->salt), (const uint8_t *)WS_TRANSPORT_INFO,
                              sizeof(WS_TRANSPORT_INFO) - 1, ctx->derivedKey);
    if (err != ESP_OK) {
        goto done;
    }

    // Create user session
    ctx->session = createSession();
    if (!ctx->session) {
        err = ESP_ERR_NO_MEM;
        goto done;
    }
    ctx->session->serverCtx = ctx->serverCtx;
    ctx->session->sockfd = httpd_req_to_sockfd(req);
    memcpy(&ctx->session->addr, &ctx->remoteAddr, sizeof(ctx->remoteAddr));
    ctx->session->userId = ctx->challengeCopy.userId;
    ctx->session->nextRxCounter = 1;
    ctx->session->nextTxCounter = 1;
    memcpy(ctx->session->sessionMasterKey, ctx->sessionMasterKey, sizeof(ctx->session->sessionMasterKey));
    memcpy(ctx->session->nonce, ctx->challengeCopy.wsNonce, sizeof(ChallengeNonce_t));
    err = aesSetKey(&ctx->session->clientAesCtx, ctx->derivedKey, AES_KEY_LEN);
    if (err != ESP_OK) {
error_destroy_session_and_done:
        decrementSessionRefCount(ctx->session);
        goto done;
    }
    err = aesSetKey(&ctx->session->serverAesCtx, ctx->derivedKey + AES_KEY_LEN, AES_KEY_LEN);
    if (err != ESP_OK) {
        goto error_destroy_session_and_done;
    }
    memcpy(ctx->session->clientBaseIV, ctx->derivedKey + 2 * AES_KEY_LEN, SESSION_IV_LEN);
    memcpy(ctx->session->serverBaseIV, ctx->derivedKey + 2 * AES_KEY_LEN + SESSION_IV_LEN, SESSION_IV_LEN);

    err = userIsAdmin(ctx->session->userId, &ctx->b);
    if (err != ESP_OK) {
        goto error_destroy_session_and_done;
    }
    ctx->session->isAdmin = (ctx->b) ? 1 : 0;

    err = userMustChangeCredentials(ctx->session->userId, &ctx->b);
    if (err != ESP_OK) {
        goto error_destroy_session_and_done;
    }
    ctx->session->mustChangeCredentials = (ctx->b) ? 1 : 0;

    // Add the session to the server's sessions list
    rwMutexLockWrite(&ctx->serverCtx->sessions.mtx);
    ctx->session->prev = ctx->serverCtx->sessions.last;
    if (ctx->serverCtx->sessions.last) {
        ctx->serverCtx->sessions.last->next = ctx->session;
    }
    else {
        ctx->serverCtx->sessions.first = ctx->session;
    }
    ctx->serverCtx->sessions.last = ctx->session;
    rwMutexUnlockWrite(&ctx->serverCtx->sessions.mtx);

    // Bind our internal session to the connection
    httpd_sess_set_ctx(req->handle, ctx->session->sockfd, ctx->session, destroySessionCtx);

    // Call session start callback
    if (handleSessionStart(ctx->session, req, &err)) {
        goto done;
    }

    // Look for existing sessions for the same user and close them
    rwMutexLockRead(&ctx->serverCtx->sessions.mtx);
    for (SessionInfo_t *otherSession = ctx->serverCtx->sessions.first;
         otherSession;
         otherSession = otherSession->next
    ) {
        // Dont close our own session
        if (otherSession->sockfd == ctx->session->sockfd) {
            continue;
        }

        if (otherSession->userId == ctx->session->userId) {
            ESP_LOGD(TAG, "Closing existing session %u for user %u.", otherSession->id, otherSession->userId);
            otherSession->isClosed = true;
            closeWs(req->handle, otherSession->sockfd, WS_CLOSE_GOING_AWAY, "User opened new session");
        }
    }
    rwMutexUnlockRead(&ctx->serverCtx->sessions.mtx);

    // Reset rate limits for successful access
    rateLimitResetAddress(&ctx->remoteAddr);

    // Continue handshake to upgrade to WebSockets
    err = ESP_OK;
    success = true;

done:
    if (!success) {
        err = httpSendInternalErrorResponse(req, err, nullptr);
        if (err == ESP_OK) {
            // If we are stopping the handshake, we must return a failure.
            err = ESP_FAIL;
        }
    }

    // Cleanup
    if (ctx->removeChallenge) {
        challengesRemove(ctx->challengeCopy.token);
    }
    p256KeyPairDone(&ctx->ecdhKeyPair);
    gbWipe(&ctx->reqQueryParams);
    gbReset(&ctx->reqQueryParams, true);
    memset(ctx, 0, sizeof(ServeWsPreHandshakeContext_t));
    free(ctx);

    // Done
    return err;
}

static esp_err_t serveWs(httpd_req_t *req)
{
    AutoRundownProtection rpLock(rp);

    if (!rpLock.acquired()) {
        return ESP_ERR_INVALID_STATE;
    }

    switch (req->method) {
        case HTTP_OPTIONS:
            return sendCORSPreflightResponse(req);

        case HTTP_GET:
            // Check if it is a real websocket request. ESP_HTTP_SERVER calls the handle even when not a websocket connection
            if (httpd_req_get_hdr_value_len(req, "Upgrade") == 0) {
                return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Not a websocket request");
            }

            // Done
            return ESP_OK;

        case 0:
            return serveWsPacket(req);
    }

    // Drop connection (should not reach here)
    return ESP_FAIL;
}

static esp_err_t serveWsPacket(httpd_req_t *req)
{
    uint8_t iv[SESSION_IV_LEN];
    PacketHeader_t *hdr;
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
        ESP_LOGD(TAG, "WebSocket session context was not found.");
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
            ESP_LOGD(TAG, "Received an invalid or unexpected WebSocket packet. Error: %d.", err);
        }
        else {
            ESP_LOGD(TAG, "Failed to read the WebSocket packet. Error: %d.", err);
        }
        return closeWsWithCmdCtxAndError(&commandCtx, "read", err);
    }
    if (!messageComplete) {
        // Nothing to do if the message is not complete
        return ESP_OK;
    }

    // We only accept binary messages
    if (commandCtx.session->incomingMessageType != IncomingBufferTypeBinary) {
        ESP_LOGD(TAG, "Received a non-binary WebSocket packet.");
        return closeWsWithCmdCtx(&commandCtx, WS_CLOSE_UNSUPPORTED_DATA, nullptr);
    }

    // Check message size (the payload may be empty, but the tag is required)
    if (commandCtx.session->ciphertextIn.used < sizeof(PacketHeader_t) + TAG_LEN) {
        ESP_LOGD(TAG, "Received a WebSocket packet that is too short.");
        return closeWsWithCmdCtx(&commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }

    // Extract header and validate version and RX counter (a.k.a. nonce)
    hdr = (PacketHeader_t *)commandCtx.session->ciphertextIn.buffer;
    if (hdr->v != VERSION) {
        ESP_LOGD(TAG, "Received a WebSocket packet with an unsupported protocol version.");
        return closeWsWithCmdCtx(&commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }
    if (hdr->flags != 0) {
        ESP_LOGD(TAG, "Received a WebSocket packet with an invalid combination of flags.");
        return closeWsWithCmdCtx(&commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }
    commandCtx.rxCounter = be64dec(hdr->counter);
    if (commandCtx.rxCounter == UINT64_MAX || commandCtx.session->nextRxCounter != commandCtx.rxCounter) {
        ESP_LOGD(TAG, "Received a WebSocket packet with an unexpected counter value.");
        return closeWsWithCmdCtx(&commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }
    commandCtx.session->nextRxCounter += 1;
    commandCtx.cmd = be16dec(hdr->cmd);
    dataAndTagLen = commandCtx.session->ciphertextIn.used - sizeof(PacketHeader_t);

    // Build IV
    memcpy(iv, commandCtx.session->clientBaseIV, SESSION_IV_LEN);
    for (size_t i = 0; i < 8; i++) {
        iv[SESSION_IV_LEN-i-1] ^= (uint8_t)((commandCtx.rxCounter >> (i << 3)) & 0xFF);
    }

    // Prepare output for decrypted message
    gbReset(&commandCtx.session->plaintextIn, false);
    if (dataAndTagLen - TAG_LEN > 0) {
        if (!gbEnsureSize(&commandCtx.session->plaintextIn, dataAndTagLen - TAG_LEN)) {
            return closeWsWithCmdCtxAndError(&commandCtx, "read", ESP_ERR_NO_MEM);
        }
    }

    // Decrypt message
    err = aesDecrypt(&commandCtx.session->clientAesCtx, commandCtx.session->ciphertextIn.buffer + sizeof(PacketHeader_t),
                     dataAndTagLen, iv, sizeof(iv), (const uint8_t *)hdr, sizeof(PacketHeader_t),
                     commandCtx.session->plaintextIn.buffer);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Failed to decrypt the WebSocket payload. Error: %d.", err);
        return closeWsWithCmdCtx(&commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }

    // Cleanup incoming message internals
    commandCtx.session->incomingMessageType = IncomingBufferTypeNone;
    gbReset(&commandCtx.session->ciphertextIn, false);

    commandCtx.br = br_init(commandCtx.session->plaintextIn.buffer, dataAndTagLen - TAG_LEN);
    return dispatchCommand(&commandCtx);
}

static esp_err_t dispatchCommand(CommandContext_t *commandCtx)
{
    incrementSessionRefCount(commandCtx->session);

    if (!commandCtx->session->dispatchMtx) {
        decrementSessionRefCount(commandCtx->session);
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(commandCtx->session->dispatchMtx, portMAX_DELAY);

    // Check if the only accepted command is to change the credentials
    if (commandCtx->session->mustChangeCredentials != 0 && commandCtx->cmd != CMD_CHANGE_USER_CREDENTIALS) {
        ESP_LOGD(TAG, "The user must change their credentials before issuing other commands.");
        esp_err_t err = closeWsWithCmdCtx(commandCtx, WS_CLOSE_APP_CREDENTIALS_CHANGE_MANDATORY, "User must change the access credentials.");
        xSemaphoreGive(commandCtx->session->dispatchMtx);
        decrementSessionRefCount(commandCtx->session);
        return err;
    }

    esp_err_t err;
    switch (commandCtx->cmd) {
        case CMD_CREATE_USER:
            err = handleCreateUser(commandCtx);
            break;

        case CMD_DELETE_USER:
            err = handleDeleteUser(commandCtx);
            break;

        case CMD_RESET_USER_CREDENTIALS:
            err = handleResetUserCredentials(commandCtx);
            break;

        case CMD_CHANGE_USER_CREDENTIALS:
            err = handleChangeUserCredentials(commandCtx);
            break;

        case CMD_OTA_BEGIN:
            err = handleOtaBegin(commandCtx);
            break;

        case CMD_OTA_WRITE:
            err = handleOtaWrite(commandCtx);
            break;

        case CMD_OTA_CANCEL:
            err = handleOtaCancel(commandCtx);
            break;

        case CMD_UDP_OPEN:
            err = handleUdpOpen(commandCtx);
            break;

        default:
            err = handleCustomCommand(commandCtx);
            break;
    }

    xSemaphoreGive(commandCtx->session->dispatchMtx);
    decrementSessionRefCount(commandCtx->session);
    return err;
}

static esp_err_t handleCreateUser(CommandContext_t *commandCtx)
{
    uint8_t flags;
    const char *name;
    size_t nameLen;
    const uint8_t *publicKey;
    uint8_t publicKeyBuf[P256_PUBLIC_KEY_SIZE];

    if (commandCtx->session->isAdmin == 0) {
        ESP_LOGD(TAG, "CREATE USER command: insufficient privileges.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Insufficient privileges", true);
    }

    // Get flags
    if (!br_read_byte(&commandCtx->br, &flags)) {
        ESP_LOGD(TAG, "CREATE USER command: invalid payload.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }
    if ((flags & (~USER_CREATE_FLAG_MUST_CHANGE_CREDENTIALS_ON_NEXT_LOGIN)) != 0) {
        ESP_LOGD(TAG, "CREATE USER command: unsupported flags.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_INVALID_ARG, "Unsupported user creation flags", true);
    }

    // Get user name
    if ((!br_read_str(&commandCtx->br, &name, &nameLen)) || nameLen == 0) {
        ESP_LOGD(TAG, "CREATE USER command: invalid payload.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }

    // Get the new public key
    if (!br_read_blob(&commandCtx->br, P256_PUBLIC_KEY_SIZE, &publicKey)) {
        ESP_LOGD(TAG, "CREATE USER command: invalid payload.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }
    memcpy(publicKeyBuf, publicKey, P256_PUBLIC_KEY_SIZE);

    // Check if the user already exists
    if (userCreate(flags, name, nameLen, publicKeyBuf) == 0) {
        ESP_LOGD(TAG, "CREATE USER command: failed to create the user.");
        return buildAndSendErrorReply(commandCtx, ESP_FAIL, "Unable to create new user", true);
    }

    // Done
    ESP_LOGD(TAG, "CREATE USER command: user created successfully.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, true);
}

static esp_err_t handleDeleteUser(CommandContext_t *commandCtx)
{
    const char *name;
    size_t nameLen;
    uint32_t targetUserId;
    bool isAdmin = false;

    if (commandCtx->session->isAdmin == 0) {
        ESP_LOGD(TAG, "DELETE USER command: insufficient privileges.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Insufficient privileges", true);
    }

    // Get user name
    if ((!br_read_str(&commandCtx->br, &name, &nameLen)) || nameLen == 0) {
        ESP_LOGD(TAG, "DELETE USER command: invalid payload.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }

    // Find the user
    targetUserId = userGetID(name, nameLen);
    if (targetUserId == 0 || userIsAdmin(targetUserId, &isAdmin) != ESP_OK) {
        ESP_LOGD(TAG, "DELETE USER command: user not found.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_FOUND, "User not found", true);
    }

    // Check if the user is admin
    if (isAdmin) {
        ESP_LOGD(TAG, "DELETE USER command: cannot delete an administrator.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Cannot delete admin user", true);
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
            ESP_LOGD(TAG, "Closing session %u for deleted user %u.", otherSession->id, otherSession->userId);
            otherSession->isClosed = true;
            closeWs(commandCtx->serverHandle, otherSession->sockfd, WS_CLOSE_GOING_AWAY, "User has been deleted");
        }
    }
    rwMutexUnlockRead(&commandCtx->serverCtx->sessions.mtx);

    // Done
    ESP_LOGD(TAG, "DELETE USER command: user deleted successfully.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, true);
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
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: insufficient privileges.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Insufficient privileges", true);
    }

    // Get user name
    if ((!br_read_str(&commandCtx->br, &name, &nameLen)) || nameLen == 0) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: invalid payload.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }

    // Get the new public key
    if (!br_read_blob(&commandCtx->br, P256_PUBLIC_KEY_SIZE, &publicKey)) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: invalid payload.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }
    memcpy(publicKeyBuf, publicKey, P256_PUBLIC_KEY_SIZE);

    // Find the user
    targetUserId = userGetID(name, nameLen);
    if (targetUserId == 0) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: user not found.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_FOUND, "User not found", true);
    }

    // Check if the user is the same than us
    if (commandCtx->session->userId == targetUserId) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: cannot reset the current user's credentials.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Cannot reset own credentials", true);
    }

    // Check if the target user is an admin
    if (userIsAdmin(targetUserId, &targetIsAdmin) != ESP_OK || targetIsAdmin) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: the target user's credentials cannot be reset.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Cannot reset user credentials", true);
    }

    // Change the user public key
    if (userChangeCredentials(targetUserId, commandCtx->session->userId, publicKeyBuf) != ESP_OK) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: failed to reset the user's credentials.");
        return buildAndSendErrorReply(commandCtx, ESP_FAIL, "Unable to reset user credentials", true);
    }

    // Delete active target user sessions
    rwMutexLockRead(&commandCtx->serverCtx->sessions.mtx);
    for (SessionInfo_t *otherSession = commandCtx->serverCtx->sessions.first; otherSession; otherSession = otherSession->next) {
        // Dont close our own session
        if (otherSession->sockfd == commandCtx->sockfd) {
            continue;
        }

        if (otherSession->userId == targetUserId) {
            ESP_LOGD(TAG, "Closing session %u for user %u after a credential reset.", otherSession->id, otherSession->userId);
            otherSession->isClosed = true;
            closeWs(commandCtx->serverHandle, otherSession->sockfd, WS_CLOSE_GOING_AWAY, "User credentials has been reset");
        }
    }
    rwMutexUnlockRead(&commandCtx->serverCtx->sessions.mtx);

    // Done
    ESP_LOGD(TAG, "RESET USER CREDENTIALS command: credentials reset successfully.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, true);
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
        ESP_LOGD(TAG, "CHANGE USER CREDENTIALS command: invalid payload.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }

    // Get the new public key
    if (!br_read_blob(&commandCtx->br, P256_PUBLIC_KEY_SIZE, &publicKey)) {
        ESP_LOGD(TAG, "CHANGE USER CREDENTIALS command: invalid payload.");
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
        ESP_LOGD(TAG, "CHANGE USER CREDENTIALS command: credential validation failed.");
        if (commandCtx->session->credentialsChangeAttempts < 2) {
            commandCtx->session->credentialsChangeAttempts += 1;
            return buildAndSendErrorReply(commandCtx, ESP_FAIL, "Validation failed", true);
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
        ESP_LOGD(TAG, "CHANGE USER CREDENTIALS command: failed to update the user's credentials.");
        return buildAndSendErrorReply(commandCtx, ESP_FAIL, "Unable to change user credentials", true);
    }

    commandCtx->session->mustChangeCredentials = 0;

    // Done
    ESP_LOGD(TAG, "CHANGE USER CREDENTIALS command: credentials updated successfully.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, true);
}

static esp_err_t handleOtaBegin(CommandContext_t *commandCtx)
{
    uint32_t imageSize;
    esp_err_t err;

    if (commandCtx->session->isAdmin == 0) {
        ESP_LOGD(TAG, "OTA BEGIN command: insufficient privileges.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Insufficient privileges", true);
    }
    if (commandCtx->session->flags & SESSION_FLAG_OTA_UPDATE) {
        ESP_LOGD(TAG, "OTA BEGIN command: an update is already active for this session.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_INVALID_STATE, "Update already active", true);
    }

    // Get the image size
    if ((!br_read_be32(&commandCtx->br, &imageSize)) || commandCtx->br.len != 0 || imageSize == 0) {
        ESP_LOGD(TAG, "OTA BEGIN command: invalid payload.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }

    // Begin OTA update
    err = otaBegin(imageSize);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "OTA BEGIN command: failed to start the update.");
        return buildAndSendErrorReply(commandCtx, err, "Failed to start update", true);
    }

    // Done
    commandCtx->session->flags |= SESSION_FLAG_OTA_UPDATE;
    ESP_LOGD(TAG, "OTA BEGIN command: update started successfully.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, true);
}

static esp_err_t handleOtaWrite(CommandContext_t *commandCtx)
{
    bool completed;
    esp_err_t err, restartErr;

    if (!(commandCtx->session->flags & SESSION_FLAG_OTA_UPDATE)) {
        ESP_LOGD(TAG, "OTA WRITE command: no update is active for this session.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_INVALID_STATE, "No update active", true);
    }

    // Get the chunk size
    if (commandCtx->br.len == 0) {
        ESP_LOGD(TAG, "OTA WRITE command: invalid payload.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }

    // Write chunk
    err = otaWrite(commandCtx->br.ptr, commandCtx->br.len, &completed);
    if (completed || err != ESP_OK) {
        commandCtx->session->flags &= ~SESSION_FLAG_OTA_UPDATE;
    }
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "OTA WRITE command: failed to write the image data.");
        return buildAndSendErrorReply(commandCtx, err, "Failed to write image data", true);
    }

    // Reply
    if (completed) {
        ESP_LOGD(TAG, "OTA WRITE command: update completed successfully; rebooting in 5 seconds...");
    }
    else {
        ESP_LOGD(TAG, "OTA WRITE command: chunk written successfully.");
    }

    err = buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, true);

    // If completed, schedule a reboot after 5 seconds. If the task creation fails, reboot immediately.
    if (completed) {
        restartErr = taskCreate(&otaRestartTask, otaRestartTaskMain, "iotcomm-restart", 2048, nullptr, 5, tskNO_AFFINITY);
        if (restartErr != ESP_OK) {
            esp_restart();
        }
    }

    // Done
    return err;
}

static esp_err_t handleOtaCancel(CommandContext_t *commandCtx)
{
    if (commandCtx->br.len != 0) {
        ESP_LOGD(TAG, "OTA CANCEL command: invalid payload.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }
    if (!(commandCtx->session->flags & SESSION_FLAG_OTA_UPDATE)) {
        ESP_LOGD(TAG, "OTA CANCEL command: no update is active for this session.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_INVALID_STATE, "No update active", true);
    }

    // Cancel current update operation
    otaCancel();
    commandCtx->session->flags &= ~SESSION_FLAG_OTA_UPDATE;

    // Done
    ESP_LOGD(TAG, "OTA CANCEL command: update canceled.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, true);
}

static esp_err_t handleUdpOpen(CommandContext_t *commandCtx)
{
    const uint8_t *clientUdpNonce;
    Sha256Context_t sha256Ctx;
    uint8_t udpSalt[SHA256_SIZE];
    uint8_t derivedKey[2 * AES_KEY_LEN + 2 * SESSION_IV_LEN];
    uint8_t reply[4 + 2 + 4 + CHALLENGE_NONCE_SIZE];
    ChallengeNonce_t serverUdpNonce;
    uint32_t udpConnectionId = 0;
    uint8_t udpClientAesKey[AES_KEY_LEN];
    uint8_t udpClientBaseIV[SESSION_IV_LEN];
    uint8_t udpConnectionIdBuf[4];
    binary_writer_t bw;
    esp_err_t err;

    if (!br_read_blob(&commandCtx->br, CHALLENGE_NONCE_SIZE, &clientUdpNonce) || commandCtx->br.len != 0) {
        ESP_LOGD(TAG, "UDP OPEN command: invalid payload.");
        return closeWsWithCmdCtx(commandCtx, WS_CLOSE_INVALID_PAYLOAD, nullptr);
    }
    if (commandCtx->serverCtx->udpListenPort == 0) {
        ESP_LOGD(TAG, "UDP OPEN command: UDP support is disabled.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_SUPPORTED, "UDP disabled", true);
    }

    memset(serverUdpNonce, 0, sizeof(serverUdpNonce));
    memset(udpClientAesKey, 0, sizeof(udpClientAesKey));
    memset(udpClientBaseIV, 0, sizeof(udpClientBaseIV));

    if (randomize(serverUdpNonce, sizeof(serverUdpNonce)) != ESP_OK)
    {
        ESP_LOGD(TAG, "UDP OPEN command: failed to allocate UDP negotiation state.");
        err = ESP_FAIL;
on_error:
        memset(serverUdpNonce, 0, sizeof(serverUdpNonce));
        memset(udpClientAesKey, 0, sizeof(udpClientAesKey));
        memset(udpClientBaseIV, 0, sizeof(udpClientBaseIV));
        memset(udpSalt, 0, sizeof(udpSalt));
        memset(derivedKey, 0, sizeof(derivedKey));
        memset(udpConnectionIdBuf, 0, sizeof(udpConnectionIdBuf));
        return buildAndSendErrorReply(commandCtx, err, "Failed to open UDP session", true);
    }
    do {
        if (randomize((uint8_t *)&udpConnectionId, sizeof(udpConnectionId)) != ESP_OK) {
            ESP_LOGD(TAG, "UDP OPEN command: failed to allocate UDP negotiation state.");
            err = ESP_FAIL;
            goto on_error;
        }
    }
    while (udpConnectionId == 0);

    // Build UDP salt = SHA256("udp-open-v1" || client_udp_nonce || server_udp_nonce || connection_id)
    sha256Init(&sha256Ctx);
    err = sha256Start(&sha256Ctx);
    if (err == ESP_OK) {
        err = sha256Update(&sha256Ctx, (const uint8_t *)"udp-open-v1", 11);
        if (err == ESP_OK) {
            err = sha256Update(&sha256Ctx, clientUdpNonce, CHALLENGE_NONCE_SIZE);
            if (err == ESP_OK) {
                err = sha256Update(&sha256Ctx, serverUdpNonce, sizeof(serverUdpNonce));
                if (err == ESP_OK) {
                    be32enc(udpConnectionIdBuf, udpConnectionId);
                    err = sha256Update(&sha256Ctx, udpConnectionIdBuf, sizeof(udpConnectionIdBuf));
                    if (err == ESP_OK) {
                        err = sha256Finish(&sha256Ctx, udpSalt);
                    }
                }
            }
        }
    }
    sha256Done(&sha256Ctx);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "UDP OPEN command: failed to derive UDP transport material.");
        err = ESP_FAIL;
        goto on_error;
    }

    err = deriveTransportKeys(commandCtx->session->sessionMasterKey, udpSalt, sizeof(udpSalt), (const uint8_t *)UDP_TRANSPORT_INFO,
                              sizeof(UDP_TRANSPORT_INFO) - 1, derivedKey);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "UDP OPEN command: failed to derive UDP transport material.");
        err = ESP_FAIL;
        goto on_error;
    }

    memcpy(udpClientAesKey, derivedKey, sizeof(udpClientAesKey));
    memcpy(udpClientBaseIV, derivedKey + 2 * AES_KEY_LEN, sizeof(udpClientBaseIV));

    bw = bw_init(reply, sizeof(reply));
    if ((!bw_write_be32(&bw, ESP_OK)) ||
        (!bw_write_be16(&bw, commandCtx->serverCtx->udpListenPort)) ||
        (!bw_write_be32(&bw, udpConnectionId)) ||
        (!bw_write_blob(&bw, serverUdpNonce, sizeof(serverUdpNonce))))
    {
        ESP_LOGD(TAG, "UDP OPEN command: failed to build reply.");
        err = ESP_FAIL;
        goto on_error;
    }

    ESP_LOGD(TAG, "UDP OPEN command: UDP negotiation parameters generated.");
    memset(udpSalt, 0, sizeof(udpSalt));
    memset(derivedKey, 0, sizeof(derivedKey));
    memset(udpConnectionIdBuf, 0, sizeof(udpConnectionIdBuf));
    err = buildAndSendReply(commandCtx, reply, bw.written, true);
    if (err == ESP_OK) {
        rwMutexLockWrite(&commandCtx->serverCtx->sessions.mtx);
        memcpy(commandCtx->session->clientUdpNonce, clientUdpNonce, sizeof(commandCtx->session->clientUdpNonce));
        memcpy(commandCtx->session->serverUdpNonce, serverUdpNonce, sizeof(commandCtx->session->serverUdpNonce));
        commandCtx->session->udpConnectionId = udpConnectionId;
        commandCtx->session->udpNextRxCounter = 1;
        memcpy(commandCtx->session->udpClientAesKey, udpClientAesKey, sizeof(commandCtx->session->udpClientAesKey));
        memcpy(commandCtx->session->udpClientBaseIV, udpClientBaseIV, sizeof(commandCtx->session->udpClientBaseIV));
        rwMutexUnlockWrite(&commandCtx->serverCtx->sessions.mtx);
    }

    memset(serverUdpNonce, 0, sizeof(serverUdpNonce));
    memset(udpClientAesKey, 0, sizeof(udpClientAesKey));
    memset(udpClientBaseIV, 0, sizeof(udpClientBaseIV));
    return err;
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
    customCommandEvent.transportType = (commandCtx->serverHandle != nullptr) ? IotCommTransportTypeWebSocket : IotCommTransportTypeUDP;
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

    if (session->flags & SESSION_FLAG_OTA_UPDATE) {
        otaCancel();
        session->flags &= ~SESSION_FLAG_OTA_UPDATE;
    }

    // Setup on-the-fly event
    memset(&otfe, 0, sizeof(otfe));
    otfe.session = session;
    otfe.event = &event;

    // Populate event data
    memset(&event, 0, sizeof(event));
    event.eventType = IotCommEventTypeSessionEnd;
    event.sessionHandle = &otfe;
    event.ctx = handlerCtx;

    // Raise event
    handler(&event);
}

static esp_err_t buildAndSendReply(CommandContext_t *commandCtx, const uint8_t *plaintextOut, size_t plaintextOutLen, bool closeOnError)
{
    return encryptAndSend(commandCtx->session, commandCtx->serverHandle, commandCtx->cmd, plaintextOut, plaintextOutLen,
                          &commandCtx->rxCounter, closeOnError);
}

static esp_err_t buildAndSendErrorReply(CommandContext_t *commandCtx, uint32_t code, const char *message, bool closeOnError)
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
    return encryptAndSend(commandCtx->session, commandCtx->serverHandle, commandCtx->cmd, buf, bufUsed, &commandCtx->rxCounter,
                          closeOnError);
}

static esp_err_t encryptAndSend(SessionInfo_t *session, httpd_handle_t serverHandle, uint16_t cmd, const uint8_t *plaintextOut,
                                size_t plaintextOutLen, const uint64_t *replyCounter, bool closeOnError)
{
    GrowableBuffer_t *ciphertextOut = &session->ciphertextOut;
    PacketHeader_t *hdr;
    uint64_t nextTxCounter;
    httpd_ws_frame_t frame;
    uint8_t iv[SESSION_IV_LEN];
    size_t toSendSize, hdrSize;
    bool fragmented;
    uint8_t *toSendPtr;
    httpd_ws_type_t toSendFrameType;
    esp_err_t err;

    if (!serverHandle) {
        return ESP_OK;
    }
    if (session->nextTxCounter == UINT64_MAX) {
        return closeWsWithSession(session, serverHandle, WS_CLOSE_INVALID_PAYLOAD, "Counter exhausted.");
    }

    // Prepare output for encrypted message
    gbReset(ciphertextOut, false);
    hdrSize = sizeof(PacketHeader_t);
    if (replyCounter) {
        hdrSize += PACKET_REPLY_COUNTER_LEN;
    }
    if (!gbEnsureSize(ciphertextOut, hdrSize + plaintextOutLen + TAG_LEN)) {
        err = ESP_ERR_NO_MEM;
on_error:
        return (closeOnError) ? closeWsWithSessionAndError(session, serverHandle, "reply", err) : err;
    }

    // Header
    hdr = (PacketHeader_t *)ciphertextOut->buffer;
    hdr->v = VERSION;
    be16enc(hdr->cmd, cmd);
    hdr->flags = (replyCounter) ? PACKET_FLAG_REPLY : 0;
    be64enc(hdr->counter, session->nextTxCounter);
    if (replyCounter) {
        be64enc(ciphertextOut->buffer + sizeof(PacketHeader_t), *replyCounter);
    }

    // Build IV
    memcpy(iv, session->serverBaseIV, SESSION_IV_LEN);
    nextTxCounter = session->nextTxCounter;
    for (size_t i = 0; i < 8; i++) {
        iv[SESSION_IV_LEN-i-1] ^= (uint8_t)((nextTxCounter >> (i << 3)) & 0xFF);
    }

    // Encrypt message
    err = aesEncrypt(&session->serverAesCtx, plaintextOut, plaintextOutLen, iv, SESSION_IV_LEN, (const uint8_t *)hdr, hdrSize,
                     ciphertextOut->buffer + hdrSize);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Failed to encrypt the WebSocket payload. Error: %d.", err);
        goto on_error;
    }

    // Send it
    toSendSize = hdrSize + plaintextOutLen + TAG_LEN;
    toSendPtr = ciphertextOut->buffer;
    toSendFrameType = HTTPD_WS_TYPE_BINARY;
    fragmented = toSendSize > MAX_OUTPUT_FRAME_SIZE;
    while (toSendSize > 0) {
        // Build frame
        memset(&frame, 0, sizeof(frame));
        frame.type = toSendFrameType;
        frame.fragmented = fragmented;
        if (toSendSize <= MAX_OUTPUT_FRAME_SIZE) {
            frame.len = toSendSize;
            frame.final = true;
        }
        else {
            frame.len = MAX_OUTPUT_FRAME_SIZE;
            frame.final = false;
        }
        frame.payload = toSendPtr;

        toSendPtr += frame.len;
        toSendSize -= frame.len;
        toSendFrameType = HTTPD_WS_TYPE_CONTINUE;

        err = httpd_ws_send_frame_async(serverHandle, session->sockfd, &frame);
        if (err != ESP_OK) {
            ESP_LOGD(TAG, "Failed to send the WebSocket frame. Error: %d.", err);
            goto on_error;
        }
    }

    // Increment TX counter
    session->nextTxCounter += 1;

    // Done
    return ESP_OK;
}

static esp_err_t closeWsWithSession(SessionInfo_t *session, httpd_handle_t serverHandle, uint16_t code, const char *reason)
{
    session->isClosed = 1;
    return closeWs(serverHandle, session->sockfd, code, reason) ? ESP_OK : ESP_FAIL;
}

static esp_err_t closeWsWithSessionAndError(SessionInfo_t *session, httpd_handle_t serverHandle, const char *zone, esp_err_t err)
{
    char reason[64];

    snprintf(reason, sizeof(reason), "%s:%d", zone, err);
    return closeWsWithSession(session, serverHandle, WS_CLOSE_INTERNAL_ERROR, reason);
}

static esp_err_t closeWsWithCmdCtx(CommandContext_t *commandCtx, uint16_t code, const char *reason)
{
    if (commandCtx->serverHandle == nullptr) {
        return ESP_OK;
    }
    if (commandCtx->session) {
        commandCtx->session->isClosed = 1;
    }
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

        if (activeServerCtx == serverCtx) {
            activeServerCtx = nullptr;
        }
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
        session->isClosed = 1;
        session->udpConnectionId = 0;
        session->udpNextRxCounter = 0;
        memset(session->clientUdpNonce, 0, sizeof(session->clientUdpNonce));
        memset(session->serverUdpNonce, 0, sizeof(session->serverUdpNonce));
        memset(session->udpClientAesKey, 0, sizeof(session->udpClientAesKey));
        memset(session->udpClientBaseIV, 0, sizeof(session->udpClientBaseIV));
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

        while (__atomic_load_n(&session->udpInFlight, __ATOMIC_ACQUIRE) != 0) {
            vTaskDelay(pdMS_TO_TICKS(1));
        }

        // Call session end callback
        handleSessionEnd(session);

        decrementSessionRefCount(session);
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
    session->refCount = 1;
    session->dispatchMtx = xSemaphoreCreateMutex();
    if (!session->dispatchMtx) {
        free(session);
        return nullptr;
    }

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

static void incrementSessionRefCount(SessionInfo_t *session)
{
    assert(session);
    __atomic_fetch_add(&session->refCount, 1, __ATOMIC_ACQ_REL);
}

static void decrementSessionRefCount(SessionInfo_t *session)
{
    assert(session);
    if (__atomic_sub_fetch(&session->refCount, 1, __ATOMIC_ACQ_REL) == 0) {
        freeSession(session);
    }
}

static void freeSession(SessionInfo_t *session)
{
    assert(session);

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
    memset(session->sessionMasterKey, 0, sizeof(session->sessionMasterKey));

    gbWipe(&session->plaintextIn);
    gbReset(&session->plaintextIn, true);
    gbWipe(&session->ciphertextIn);
    gbReset(&session->ciphertextIn, true);
    gbWipe(&session->ciphertextOut);
    gbReset(&session->ciphertextOut, true);
    if (session->dispatchMtx) {
        vSemaphoreDelete(session->dispatchMtx);
        session->dispatchMtx = nullptr;
    }
    memset(session, 0, sizeof(SessionInfo_t));
    free(session);
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

static void otaRestartTaskMain(Task_t *task, void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(5000));
    esp_restart();
}

static esp_err_t startUdpServer(ServerContext_t *serverCtx)
{
    struct sockaddr_in addr;
    esp_err_t err;

    stopUdpServer();

    udpServerSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (udpServerSocket < 0) {
        ESP_LOGE(TAG, "Failed to create the UDP socket.");
        return ESP_FAIL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(serverCtx->udpListenPort);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(udpServerSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind the UDP socket.");
        close(udpServerSocket);
        udpServerSocket = -1;
        return ESP_FAIL;
    }

    err = taskCreate(&udpServerTask, udpServerTaskMain, "iotcomm-udp", 6144, serverCtx, 4, tskNO_AFFINITY);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start the UDP server task. Error: %d.", err);
        close(udpServerSocket);
        udpServerSocket = -1;
        return err;
    }

    ESP_LOGI(TAG, "UDP server listening on port %u.", serverCtx->udpListenPort);
    return ESP_OK;
}

static void stopUdpServer()
{
    if (taskIsRunning(&udpServerTask)) {
        if (udpServerSocket >= 0) {
            close(udpServerSocket);
            udpServerSocket = -1;
        }

        taskJoin(&udpServerTask);
        taskInit(&udpServerTask);
    }
    else if (udpServerSocket >= 0) {
        close(udpServerSocket);
        udpServerSocket = -1;
    }
}

static void udpServerTaskMain(Task_t *task, void *arg)
{
    ServerContext_t *serverCtx = (ServerContext_t *)arg;
    uint8_t *rxBuffer;

    taskSignalContinue(task);

    rxBuffer = (uint8_t *)malloc(serverCtx->maxPacketSize);
    if (!rxBuffer) {
        ESP_LOGE(TAG, "Failed to allocate the UDP receive buffer.");
        return;
    }

    while (!taskShouldQuit(task)) {
        struct sockaddr_storage srcAddr = {};
        socklen_t srcAddrLen = sizeof(srcAddr);
        IPAddress_t remoteAddr;
        int len;

        len = recvfrom(udpServerSocket, rxBuffer, serverCtx->maxPacketSize, 0, (struct sockaddr *)&srcAddr, &srcAddrLen);
        if (taskShouldQuit(task)) {
            break;
        }
        if (len <= 0) {
            continue;
        }

        switch (srcAddr.ss_family) {
            case AF_INET:
                parseIPv4(&remoteAddr, (const struct sockaddr_in *)&srcAddr);
                break;

            case AF_INET6:
                parseIPv6(&remoteAddr, (const struct sockaddr_in6 *)&srcAddr);
                break;

            default:
                continue;
        }

        processUdpPacket(serverCtx, rxBuffer, (size_t)len, &remoteAddr);
    }

    free(rxBuffer);
}

static void processUdpPacket(ServerContext_t *serverCtx, const uint8_t *packet, size_t packetLen, const IPAddress_t *remoteAddr)
{
    const UdpPacketHeader_t *hdr;
    SessionInfo_t *session = nullptr;
    uint32_t udpConnectionId;
    uint64_t rxCounter;
    uint64_t expectedRxCounter = 0;
    uint8_t udpClientAesKey[AES_KEY_LEN];
    uint8_t udpClientBaseIV[SESSION_IV_LEN];
    uint8_t iv[SESSION_IV_LEN];
    uint8_t *plaintext = nullptr;
    size_t ciphertextLen;
    size_t plaintextLen;
    AesContext_t aesCtx;
    CommandContext_t commandCtx;
    esp_err_t err;

    if (packetLen < sizeof(UdpPacketHeader_t) + TAG_LEN) {
        return;
    }

    hdr = (const UdpPacketHeader_t *)packet;
    if (hdr->packetHeader.v != VERSION || hdr->packetHeader.flags != 0) {
        return;
    }

    udpConnectionId = be32dec(hdr->udpConnectionId);
    rxCounter = be64dec(hdr->packetHeader.counter);
    if (rxCounter == UINT64_MAX) {
        return;
    }
    ciphertextLen = packetLen - sizeof(UdpPacketHeader_t);
    plaintextLen = ciphertextLen - TAG_LEN;

    rwMutexLockRead(&serverCtx->sessions.mtx);
    for (SessionInfo_t *candidate = serverCtx->sessions.first; candidate; candidate = candidate->next) {
        if (candidate->isClosed == 0 && candidate->udpConnectionId == udpConnectionId && ipAddressEqual(&candidate->addr, remoteAddr)) {
            session = candidate;
            incrementSessionRefCount(session);
            __atomic_fetch_add(&session->udpInFlight, 1, __ATOMIC_ACQ_REL);
            expectedRxCounter = session->udpNextRxCounter;
            memcpy(udpClientAesKey, session->udpClientAesKey, sizeof(udpClientAesKey));
            memcpy(udpClientBaseIV, session->udpClientBaseIV, sizeof(udpClientBaseIV));
            break;
        }
    }
    rwMutexUnlockRead(&serverCtx->sessions.mtx);

    if (!session) {
        return;
    }

    if (rxCounter < expectedRxCounter) {
        goto done;
    }

    if (plaintextLen > 0) {
        plaintext = (uint8_t *)malloc(plaintextLen);
        if (!plaintext) {
            goto done;
        }
    }

    memcpy(iv, udpClientBaseIV, sizeof(iv));
    for (size_t i = 0; i < 8; i++) {
        iv[SESSION_IV_LEN - i - 1] ^= (uint8_t)((rxCounter >> (i << 3)) & 0xFF);
    }

    aesInit(&aesCtx);
    err = aesSetKey(&aesCtx, udpClientAesKey, sizeof(udpClientAesKey));
    if (err == ESP_OK) {
        err = aesDecrypt(&aesCtx, packet + sizeof(UdpPacketHeader_t), ciphertextLen, iv, sizeof(iv), (const uint8_t *)hdr,
                         sizeof(UdpPacketHeader_t), plaintext);
    }
    aesDone(&aesCtx);
    if (err != ESP_OK) {
        goto done;
    }

    memset(&commandCtx, 0, sizeof(commandCtx));
    commandCtx.serverCtx = serverCtx;
    commandCtx.sockfd = udpServerSocket;
    commandCtx.session = session;
    commandCtx.cmd = be16dec(hdr->packetHeader.cmd);
    commandCtx.br = br_init(plaintext, plaintextLen);
    commandCtx.rxCounter = rxCounter;
    dispatchCommand(&commandCtx);

    if (session->udpConnectionId == udpConnectionId && session->udpNextRxCounter <= rxCounter) {
        if (rxCounter == UINT64_MAX - 1) {
            session->udpConnectionId = 0;
            session->udpNextRxCounter = 0;
            memset(session->clientUdpNonce, 0, sizeof(session->clientUdpNonce));
            memset(session->serverUdpNonce, 0, sizeof(session->serverUdpNonce));
            memset(session->udpClientAesKey, 0, sizeof(session->udpClientAesKey));
            memset(session->udpClientBaseIV, 0, sizeof(session->udpClientBaseIV));
        }
        else {
            session->udpNextRxCounter = rxCounter + 1;
        }
    }

done:
    if (plaintext) {
        free(plaintext);
    }
    __atomic_fetch_sub(&session->udpInFlight, 1, __ATOMIC_ACQ_REL);
    decrementSessionRefCount(session);
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

static bool extGbAddBool(GrowableBuffer_t *buf, bool value)
{
    return gbAdd(buf, value ? "true" : "false", value ? 4 : 5);
}

static bool extGbAddSizeT(GrowableBuffer_t *buf, size_t value)
{
    char text[3 * sizeof(value) + 1];
    int textLen;

    textLen = snprintf(text, sizeof(text), "%zu", value);
    return textLen > 0 && (size_t)textLen < sizeof(text) && gbAdd(buf, text, (size_t)textLen);
}

static esp_err_t sha256Build(uint8_t hash[SHA256_SIZE], const uint8_t *const *parts, const size_t *partLens, size_t partsCount)
{
    Sha256Context_t sha256Ctx;
    esp_err_t err;

    sha256Init(&sha256Ctx);
    err = sha256Start(&sha256Ctx);
    for (size_t i = 0; err == ESP_OK && i < partsCount; i++) {
        if (partLens[i] == 0) {
            continue;
        }
        err = sha256Update(&sha256Ctx, parts[i], partLens[i]);
    }
    if (err == ESP_OK) {
        err = sha256Finish(&sha256Ctx, hash);
    }
    sha256Done(&sha256Ctx);
    return err;
}

static esp_err_t buildWsServerAuthHash(const Challenge_t *challenge, uint8_t hash[SHA256_SIZE])
{
    static const uint8_t label[] = "ws-login-v1/server-auth";
    const uint8_t *parts[] = {
        label,
        challenge->ecdhClientPublicKey,
        challenge->ecdhServerPublicKey,
        challenge->clientNonce,
        challenge->serverNonce,
        challenge->token
    };
    const size_t partLens[] = {
        sizeof(label) - 1,
        sizeof(challenge->ecdhClientPublicKey),
        sizeof(challenge->ecdhServerPublicKey),
        sizeof(challenge->clientNonce),
        sizeof(challenge->serverNonce),
        sizeof(challenge->token)
    };

    return sha256Build(hash, parts, partLens, sizeof(parts) / sizeof(parts[0]));
}

static esp_err_t buildWsUserAuthHash(const Challenge_t *challenge, const uint8_t authNonce[CHALLENGE_NONCE_SIZE], const char *userName,
                                     size_t userNameLen, uint8_t hash[SHA256_SIZE])
{
    static const uint8_t label[] = "ws-login-v1/user-auth";
    const uint8_t *parts[] = {
        label,
        challenge->ecdhClientPublicKey,
        challenge->ecdhServerPublicKey,
        challenge->clientNonce,
        challenge->serverNonce,
        challenge->token,
        authNonce,
        (const uint8_t *)userName
    };
    const size_t partLens[] = {
        sizeof(label) - 1,
        sizeof(challenge->ecdhClientPublicKey),
        sizeof(challenge->ecdhServerPublicKey),
        sizeof(challenge->clientNonce),
        sizeof(challenge->serverNonce),
        sizeof(challenge->token),
        CHALLENGE_NONCE_SIZE,
        userNameLen
    };

    return sha256Build(hash, parts, partLens, sizeof(parts) / sizeof(parts[0]));
}

static esp_err_t deriveWsLoginSalt(const Challenge_t *challenge, const uint8_t *extra, size_t extraLen, uint8_t salt[SHA256_SIZE])
{
    static const uint8_t label[] = "ws-login-v1";
    const uint8_t *parts[] = {
        label,
        challenge->serverNonce,
        challenge->clientNonce,
        challenge->token,
        extra
    };
    const size_t partLens[] = {
        sizeof(label) - 1,
        sizeof(challenge->serverNonce),
        sizeof(challenge->clientNonce),
        sizeof(challenge->token),
        extraLen
    };

    return sha256Build(salt, parts, partLens, sizeof(parts) / sizeof(parts[0]));
}

static esp_err_t deriveSessionMasterKey(const uint8_t sharedSecret[P256_SHARED_SECRET_SIZE], const uint8_t *salt, size_t saltLen,
                                        uint8_t sessionMasterKey[SESSION_AES_KEY_LEN])
{
    return hkdfSha256DeriveKey(sharedSecret, P256_SHARED_SECRET_SIZE, salt, saltLen, (const uint8_t *)SESSION_MASTER_INFO,
                               sizeof(SESSION_MASTER_INFO) - 1, sessionMasterKey, SESSION_AES_KEY_LEN);
}

static esp_err_t deriveAuthEnvelopeKey(const uint8_t sharedSecret[P256_SHARED_SECRET_SIZE], const uint8_t salt[SHA256_SIZE],
                                       uint8_t authKey[AES_KEY_LEN])
{
    return hkdfSha256DeriveKey(sharedSecret, P256_SHARED_SECRET_SIZE, salt, SHA256_SIZE, (const uint8_t *)AUTH_ENVELOPE_INFO,
                               sizeof(AUTH_ENVELOPE_INFO) - 1, authKey, AES_KEY_LEN);
}

static esp_err_t deriveTransportKeys(const uint8_t sessionMasterKey[SESSION_AES_KEY_LEN], const uint8_t *salt, size_t saltLen,
                                     const uint8_t *info, size_t infoLen,
                                     uint8_t derivedKey[2 * AES_KEY_LEN + 2 * SESSION_IV_LEN])
{
    return hkdfSha256DeriveKey(sessionMasterKey, SESSION_AES_KEY_LEN, salt, saltLen, info, infoLen, derivedKey,
                               2 * AES_KEY_LEN + 2 * SESSION_IV_LEN);
}

static esp_err_t sendCORSPreflightResponse(httpd_req_t *req)
{
    char *corsOrigin = nullptr;
    esp_err_t err;

    err = httpGetCORSOrigin(req, &corsOrigin);
    if (err == ESP_OK) {
        err = httpSendPreflightResponse(req, corsOrigin);
    }

    // Done
    httpFreeCORSOrigin(corsOrigin);
    return err;
}

static bool tryExtractWsTicketFromQuery(const char *query, char *ticketB64, size_t ticketB64Len, bool *selected)
{
    assert(ticketB64);
    assert(selected);

    *selected = false;
    if ((!query) || (*query == 0)) {
        return true;
    }
    if (!strstr(query, "wsTicket=")) {
        return true;
    }

    *selected = true;
    return httpd_query_key_value(query, "wsTicket", ticketB64, ticketB64Len) == ESP_OK && ticketB64[0] != 0;
}

static bool tryExtractWsTicketFromAuthorization(httpd_req_t *req, char *ticketB64, size_t ticketB64Len, bool *selected)
{
    size_t authLen;
    char *authHeader;
    bool ok;

    assert(req);
    assert(ticketB64);
    assert(selected);

    *selected = false;

    authLen = httpd_req_get_hdr_value_len(req, "Authorization");
    if (authLen == 0) {
        return true;
    }

    authHeader = (char *)malloc(authLen + 1);
    if (!authHeader) {
        return false;
    }

    *selected = true;
    ok = httpd_req_get_hdr_value_str(req, "Authorization", authHeader, authLen + 1) == ESP_OK &&
         authLen > 7 &&
         memcmp(authHeader, "Bearer ", 7) == 0 &&
         authHeader[7] != 0 &&
         strlen(authHeader + 7) < ticketB64Len;
    if (ok) {
        strcpy(ticketB64, authHeader + 7);
    }

    memset(authHeader, 0, authLen + 1);
    free(authHeader);
    return ok;
}
