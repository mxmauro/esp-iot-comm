#include "iot_comm/iot_comm.h"
#include "esp_err.h"
#include "http_parser.h"
#include "iot_comm/binary_reader.h"
#include "iot_comm/crypto/aes.h"
#include "iot_comm/crypto/hash.h"
#include "challenge.h"
#include "ip_address.h"
#include "lwip/sockets.h"
#include "rate_limit.h"
#include "user.h"
#include <atomic>
#include <convert.h>
#include <cJSON.h>
#include <cstddef>
#include <cstdint>
#include <endian.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <growable_buffer.h>
#include <lwip/sockets.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mutex.h>
#include <stdint.h>
#include <sys/_types.h>

static const char* TAG = "IotComm";

#define VERSION 1

#define TAG_LEN     16
#define AES_KEY_LEN 32

#define MAX_BODY_SIZE 10240
#define MAX_QUERY_SIZE 1024
#define MAX_MSG_SIZE 2000

#define CMD_CREATE_USER             0x7FF1
#define CMD_DELETE_USER             0x7FF2
#define CMD_RESET_USER_CREDENTIALS  0x7FF3
#define CMD_CHANGE_USER_CREDENTIALS 0x7FF4

#define SESSION_IV_LEN     12
#define SESSION_AES_KEY_LEN    32

// -----------------------------------------------------------------------------

typedef struct ServerContext_s {
    GrowableBuffer_t plaintext;
    GrowableBuffer_t ciphertext;

    size_t maxConnectionsCount;
    int *clientSocketsBuffer;
} ServerContext_t;

typedef struct SessionInfo_s {
    uint32_t id;
    int sockfd;
    void *userData;
    IotCommUserDataFreeFunc_t userDataFreeFn;
    IPAddress_t addr;
    uint32_t userId;
    uint32_t nextRxCounter;
    uint32_t nextTxCounter;
    ChallengeNonce_t nonce;
    uint8_t clientAesKey[SESSION_AES_KEY_LEN];
    uint8_t clientBaseIV[SESSION_IV_LEN];
    uint8_t serverAesKey[SESSION_AES_KEY_LEN];
    uint8_t serverBaseIV[SESSION_IV_LEN];
    uint8_t isAdmin : 1;
    uint8_t mustChangeCredentials : 1;
    uint8_t credentialsChangeAttempts : 2;
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

// -----------------------------------------------------------------------------

static Mutex mtx;
static httpd_handle_t server = nullptr;
static std::atomic_uint32_t nextSessionId = {0};
static IotCommEventHandler_t handler = nullptr;

// -----------------------------------------------------------------------------

static void internalServerStop();

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

static esp_err_t handleSessionStart(SessionInfo_t *session);
static void handleSessionEnd(SessionInfo_t *session);

static esp_err_t buildAndSendReply(CommandContext_t *commandCtx, const uint8_t *plaintext, size_t plaintextLen, uint32_t replyCounter);
static esp_err_t buildAndSendErrorReply(CommandContext_t *commandCtx, uint32_t code, const char *message, uint32_t replyCounter);

static const char *parseRequestBody(ServerContext_t *serverCtx, httpd_req_t *req, size_t *rawBodyLen);
static const char *parseRequestQuery(ServerContext_t *serverCtx, httpd_req_t *req);
static esp_err_t setDefaultCORS(httpd_req_t *req);

static bool getClientIpFromRequest(httpd_req_t *req, IPAddress_t *out);
static bool getIpFromPeer(int sockfd, IPAddress_t *out);

static void destroyServerCtx(void *ctx);
static void destroySessionCtx(void *ctx);

static esp_err_t readWsPacket(ServerContext_t *serverCtx, httpd_req_t *req, httpd_ws_frame_t *frame);
static void closeWebsocket(httpd_handle_t serverHandle, int sockfd, uint16_t code, const char *reason);

static bool extGbAddB64(GrowableBuffer_t *buf, const uint8_t *src, size_t srcLen, bool isUrl);

// -----------------------------------------------------------------------------

esp_err_t iotCommInit(IotCommConfig_t *config)
{
    httpd_config_t httpdConfig;
    ServerContext_t *serverCtx;
    httpd_uri_t uri;
    esp_err_t err;

    assert(config);
    assert(config->listenPort >= 1);
    assert(config->maxConnections >= 1);
    assert(config->handler);

    internalServerStop();

    nextSessionId.store(1);

    // Initialize crypto
    err = p256Init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to load ECP group. Error: %d", err);
        return err;
    }

    // Initialize helpers
    err = usersInit(config->maxUsersCount, config->usersStorage, config->fnGetDefRootUserPublicKey);
    if (err == ESP_OK) {
        uint8_t maxRequestsPerWindow = config->maxRequestsPerWindow;

        // The authentication flow is INIT+AUTH+WS so let's multiply the provided request limit by three.
        if (maxRequestsPerWindow < ((sizeof(maxRequestsPerWindow) << 8) - 1) / 3) {
            maxRequestsPerWindow *= 3;
        }
        else {
            maxRequestsPerWindow = (uint8_t)((sizeof(maxRequestsPerWindow) << 8) - 1);
        }

        err = rateLimitInit(config->maxRateLimitSlots, config->rateLimitWindowSizeInMs, maxRequestsPerWindow,
                            config->maxConsecutiveAuthFailures);
    }
    if (err == ESP_OK) {
        err = challengesInit(config->maxChallengesSlot, config->challengeWindowSizeInMs);
    }
    if (err != ESP_OK) {
        goto on_error;
    }

    // Create http server context
    serverCtx = (ServerContext_t *)malloc(sizeof(ServerContext_t));
    if (!serverCtx) {
        err = ESP_ERR_NO_MEM;
        goto on_error;
    }
    serverCtx->plaintext = GB_STATIC_INIT;
    serverCtx->ciphertext = GB_STATIC_INIT;
    serverCtx->maxConnectionsCount = config->maxConnections;
    serverCtx->clientSocketsBuffer = (int *)malloc(config->maxConnections * sizeof(int));
    if (!serverCtx->clientSocketsBuffer) {
        free(serverCtx);
        err = ESP_ERR_NO_MEM;
        goto on_error;
    }

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

    // Save event handler
    handler = config->handler;

    // Done
    ESP_LOGI(TAG, "Server initialized and listening at %u", config->listenPort);
    return ESP_OK;

on_error:
    ESP_LOGE(TAG, "Unable to start http server. Error: %d.", err);
    internalServerStop();
    return err;
}

void iotCommDone()
{
    AutoMutex lock(&mtx);

    internalServerStop();
    challengesDone();
    rateLimitDone();
    usersDone();
    p256Done();

    handler = nullptr;
}

bool iotCommIsRunning()
{
    AutoMutex lock(&mtx);

    return !!server;
}

// -----------------------------------------------------------------------------

static void internalServerStop()
{
    if (server) {
        httpd_stop(server);
        server = nullptr;
    }
}

static esp_err_t serveWsInit(httpd_req_t *req)
{
    ServerContext_t *serverCtx = (ServerContext_t *)httpd_get_global_user_ctx(req->handle);
    IPAddress_t remoteAddr;
    const char *rawBody;
    size_t rawBodyLen;
    cJSON *json, *userNameItem, *clientNonceItem, *ecdhClientPublicKeyItem;
    size_t clientNonceLen;
    size_t ecdhClientPublicKeyLen;
    Challenge_t challenge;
    ChallengeCookie_t challengeCookie;
    ECDHKeyPair ecdhKeyPair;
    GrowableBuffer_t *outBuf = nullptr;
    esp_err_t err;

    err = setDefaultCORS(req);
    if (err != ESP_OK) {
        goto done;
    }

    // Is OPTIONS?
    if (req->method == HTTP_OPTIONS) {
        httpd_resp_set_status(req, HTTPD_204);
        httpd_resp_send(req, nullptr, 0);
        return ESP_OK;
    }

    // Get request IP address
    if (!getClientIpFromRequest(req, &remoteAddr)) {
        ESP_LOGE(TAG, "Failed to get client IP address");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, nullptr);
        return ESP_FAIL;
    }

    // Check rate limit
    if (!rateLimitCheckRequest(&remoteAddr)) {
        httpd_resp_send_custom_err(req, "429 Too Many Requests", "");
        return ESP_FAIL;
    }

    // Prepare challenge
    memset(&challenge, 0, sizeof(challenge));

    // Read request body
    rawBody = parseRequestBody(serverCtx, req, &rawBodyLen);
    if (!rawBody) {
        err = ESP_FAIL;
        goto done;
    }

    // Extract parameters from request body and validate
    json = cJSON_ParseWithLength(rawBody, rawBodyLen);
    if (!json) {
error400:
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid parameters");
        err = ESP_FAIL;
        goto done;
    }
    userNameItem = cJSON_GetObjectItem(json, "userName");
    clientNonceItem = cJSON_GetObjectItem(json, "clientNonce");
    ecdhClientPublicKeyItem = cJSON_GetObjectItem(json, "clientPublicKey");
    if ((!cJSON_IsString(userNameItem)) || (!userNameItem->valuestring) || *userNameItem->valuestring == 0 ||
        (!cJSON_IsString(clientNonceItem)) || (!clientNonceItem->valuestring) ||
        (!cJSON_IsString(ecdhClientPublicKeyItem)) || (!ecdhClientPublicKeyItem->valuestring)
    ) {
error400_del_json:
        cJSON_Delete(json);
        goto error400;
    }

    // Validate user
    challenge.userId = userGetID(userNameItem->valuestring, strlen(userNameItem->valuestring));
    if (challenge.userId == 0) {
        goto error400_del_json;
    }

    // Decode and validate client nonce and client ECDH public key
    clientNonceLen = sizeof(challenge.clientNonce);
    ecdhClientPublicKeyLen = sizeof(challenge.ecdhClientPublicKey);
    if ((!fromB64(clientNonceItem->valuestring, strlen(clientNonceItem->valuestring), false,
            challenge.clientNonce, &clientNonceLen)) ||
        (!fromB64(ecdhClientPublicKeyItem->valuestring, strlen(ecdhClientPublicKeyItem->valuestring), false,
            challenge.ecdhClientPublicKey, &ecdhClientPublicKeyLen))
    ) {
        goto error400_del_json;
    }
    if (clientNonceLen != CHALLENGE_NONCE_SIZE || ecdhClientPublicKeyLen != P256_PUBLIC_KEY_SIZE ||
        (!P256KeyPair::validatePublicKey(challenge.ecdhClientPublicKey, P256_PUBLIC_KEY_SIZE))
    ) {
        goto error400_del_json;
    }

    // Cleanup json data
    cJSON_Delete(json);

    // Generate server nonce, challenge cookie and ephemeral server ECDH key pair
    if ((!randomize(challenge.serverNonce, sizeof(challenge.serverNonce))) ||
        (!randomize(challengeCookie, sizeof(challengeCookie))) ||
        ecdhKeyPair.generate() != ESP_OK ||
        ecdhKeyPair.savePublicKey(challenge.ecdhServerPublicKey) != ESP_OK ||
        ecdhKeyPair.savePrivateKey(challenge.ecdhServerPrivateKey) != ESP_OK
    ) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to generate challenge");
        err = ESP_FAIL;
        goto done;
    }

    // Add the new challenge
    challengesAdd(challengeCookie, &remoteAddr, &challenge);

    // Prepare output
    err = httpd_resp_set_type(req, "application/json");
    if (err != ESP_OK) {
error500:
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
            ((err == ESP_ERR_NO_MEM) ? "Insufficient resources" : nullptr));
        err = ESP_FAIL;
        goto done;
    }

    // Write output
    outBuf = &serverCtx->plaintext;
    gbReset(outBuf, false);

    if ((!gbAdd(outBuf, "{\"token\":\"", 10)) ||
        (!extGbAddB64(outBuf, challengeCookie, sizeof(challengeCookie), false)) ||
        (!gbAdd(outBuf, "\",\"serverNonce\":\"", 17)) ||
        (!extGbAddB64(outBuf, challenge.serverNonce, sizeof(challenge.serverNonce), false)) ||
        (!gbAdd(outBuf, "\",\"serverPublicKey\":\"", 21)) ||
        (!extGbAddB64(outBuf, challenge.ecdhServerPublicKey, sizeof(challenge.ecdhServerPublicKey), false)) ||
        (!gbAdd(outBuf, "\"}", 2))
    ) {
        err = ESP_ERR_NO_MEM;
        goto error500;
    }

    err = httpd_resp_send(req, (char *)outBuf->buffer, (ssize_t)outBuf->used);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Unable to deliver response");
        err = ESP_FAIL;
        goto done;
    }

    // Success
    err = ESP_OK;

done:
    if (outBuf) {
        gbWipe(outBuf);
    }
    memset(&challenge, 0, sizeof(challenge));
    return err;
}

static esp_err_t serveWsAuth(httpd_req_t *req)
{
    ServerContext_t *serverCtx = (ServerContext_t *)httpd_get_global_user_ctx(req->handle);
    IPAddress_t remoteAddr;
    const char *rawBody;
    size_t rawBodyLen;
    cJSON *json, *cookieItem, *authNonceItem, *signatureItem;
    ChallengeCookie_t challengeCookie;
    uint8_t authNonce[CHALLENGE_NONCE_SIZE];
    uint8_t signature[P256_SIGNATURE_SIZE];
    size_t challengeCookieLen;
    size_t authNonceLen;
    size_t signatureLen;
    Challenge_t *challenge;
    Sha256 hash256;
    uint8_t th[SHA256_SIZE];
    GrowableBuffer_t *outBuf = nullptr;
    bool b;
    esp_err_t err;

    err = setDefaultCORS(req);
    if (err != ESP_OK) {
        goto done;
    }

    // Is OPTIONS?
    if (req->method == HTTP_OPTIONS) {
        httpd_resp_set_status(req, HTTPD_204);
        httpd_resp_send(req, nullptr, 0);
        return ESP_OK;
    }

    // Get request IP address
    if (!getClientIpFromRequest(req, &remoteAddr)) {
        ESP_LOGE(TAG, "Failed to get client IP address");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, nullptr);
        return ESP_FAIL;
    }

    // Check rate limit
    if (!rateLimitCheckRequest(&remoteAddr)) {
        httpd_resp_send_custom_err(req, "429 Too Many Requests", "");
        return ESP_FAIL;
    }

    // Read request body
    rawBody = parseRequestBody(serverCtx, req, &rawBodyLen);
    if (!rawBody) {
        err = ESP_FAIL;
        goto done;
    }

    // Extract parameters from request body and validate
    json = cJSON_ParseWithLength(rawBody, rawBodyLen);
    if (!json) {
error400:
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid parameters");
        err = ESP_FAIL;
        goto done;
    }

    cookieItem = cJSON_GetObjectItem(json, "token");
    authNonceItem = cJSON_GetObjectItem(json, "authNonce");
    signatureItem = cJSON_GetObjectItem(json, "signature");
    if ((!cJSON_IsString(cookieItem)) || (!cookieItem->valuestring) ||
        (!cJSON_IsString(authNonceItem)) || (!authNonceItem->valuestring) ||
        (!cJSON_IsString(signatureItem)) || (!signatureItem->valuestring)
    ) {
error400_del_json:
        cJSON_Delete(json);
        goto error400;
    }

    // Decode and validate token, auth nonce, and signature
    challengeCookieLen = sizeof(challengeCookie);
    authNonceLen = sizeof(authNonce);
    signatureLen = sizeof(signature);
    if ((!fromB64(cookieItem->valuestring, strlen(cookieItem->valuestring), false, challengeCookie, &challengeCookieLen)) ||
        (!fromB64(authNonceItem->valuestring, strlen(authNonceItem->valuestring), false, authNonce, &authNonceLen)) ||
        (!fromB64(signatureItem->valuestring, strlen(signatureItem->valuestring), false, signature, &signatureLen))
    ) {
        goto error400_del_json;
    }
    if (challengeCookieLen != CHALLENGE_COOKIE_SIZE || authNonceLen != CHALLENGE_NONCE_SIZE || signatureLen != P256_SIGNATURE_SIZE) {
        goto error400_del_json;
    }

    // Cleanup json data
    cJSON_Delete(json);

    // Lookup challenge
    challenge = challengesFind(challengeCookie, &remoteAddr);
    if (!challenge) {
error401_nc:
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, nullptr);
        err = ESP_FAIL;
        goto done;
    }

    // th = SHA256("ws-login-v1" || c_pk || s_pk || s_nonce || c_nonce || cookie || auth_nonce)
    hash256.init();
    hash256.update("ws-login-v1", 11);
    hash256.update(challenge->ecdhServerPublicKey, sizeof(challenge->ecdhServerPublicKey));
    hash256.update(challenge->ecdhClientPublicKey, sizeof(challenge->ecdhClientPublicKey));
    hash256.update(challenge->serverNonce, sizeof(challenge->serverNonce));
    hash256.update(challenge->clientNonce, sizeof(challenge->clientNonce));
    hash256.update(challengeCookie, sizeof(challengeCookie));
    hash256.update(authNonce, sizeof(authNonce));
    hash256.finalize(th);
    if (hash256.error() != ESP_OK) {
error401:
        challengesRemove(challengeCookie);
        goto error401_nc;
    }

    // Verify signature of th
    err = userVerifySignature(challenge->userId, th, signature);
    if (err != ESP_OK) {
        if (err == MBEDTLS_ERR_ECP_VERIFY_FAILED) {
            goto error401;
        }
error500:
        challengesRemove(challengeCookie);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, ((err == ESP_ERR_NO_MEM) ? "Insufficient resources" : nullptr));
        goto done;
    }

    // Mark challenge as verified
    challenge->verified = true;

    // Generate ws nonce
    if (!randomize(challenge->wsNonce, sizeof(challenge->wsNonce))) {
        goto error500;
    }

    // Prepare output
    err = httpd_resp_set_type(req, "application/json");
    if (err != ESP_OK) {
        goto error500;
    }

    // Write output
    outBuf = &serverCtx->plaintext;
    gbReset(outBuf, false);

    if (!(gbAdd(outBuf, "{\"mustChangeCredentials\":", 25))) {
error500_nomem:
        err = ESP_ERR_NO_MEM;
        goto error500;
    }
    userMustChangeCredentials(challenge->userId, &b); // error check ignored on purpose
    if (b) {
        if (!gbAdd(outBuf, "true", 4)) {
            goto error500_nomem;
        }
    }
    else {
        if (!gbAdd(outBuf, "false", 5)) {
            goto error500_nomem;
        }
    }

    if ((!gbAdd(outBuf, ",\"wsNonce\":\"", 12)) ||
        (!extGbAddB64(outBuf, challenge->wsNonce, sizeof(challenge->wsNonce), false)) ||
        (!gbAdd(outBuf, "\"}", 2))
    ) {
        goto error500_nomem;
    }

    err = httpd_resp_send(req, (char *)outBuf->buffer, (ssize_t)outBuf->used);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Unable to deliver response");
        err = ESP_FAIL;
        goto done;
    }

    // Success
    err = ESP_OK;

done:
    // Cleanup
    if (outBuf) {
        gbWipe(outBuf);
    }
    memset(th, 0, sizeof(th));
    memset(signature, 0, sizeof(signature));
    memset(authNonce, 0, sizeof(authNonce));
    memset(&challengeCookie, 0, sizeof(challengeCookie));
    return err;
}

static esp_err_t serveWs(httpd_req_t *req)
{
    if (req->method == 0) {
        return serveWsPacket(req);
    }
    return serveWsUpgrade(req);
}

static esp_err_t serveWsUpgrade(httpd_req_t *req)
{
    ServerContext_t *serverCtx = (ServerContext_t *)httpd_get_global_user_ctx(req->handle);
    IPAddress_t remoteAddr;
    const char *rawQuery;
    char tokenB64[CHALLENGE_COOKIE_SIZE * 4 / 3 + 2];
    char wsNonceB64[CHALLENGE_NONCE_SIZE * 4 / 3 + 2];
    char signatureB64[P256_SIGNATURE_SIZE * 4 / 3 + 2];
    ChallengeCookie_t challengeCookie;
    ChallengeNonce_t wsNonce;
    uint8_t signature[P256_SIGNATURE_SIZE];
    size_t challengeCookieLen;
    size_t wsNonceLen;
    size_t signatureLen;
    Challenge_t *challenge;
    Sha256 hash256;
    uint8_t th[SHA256_SIZE];
    ECDHKeyPair ecdhKeyPair;
    uint8_t info[6 + 2 * P256_PUBLIC_KEY_SIZE];
    uint8_t salt[SHA256_SIZE];
    uint8_t sharedSecret[AES_KEY_LEN];
    uint8_t derivedKey[2 * AES_KEY_LEN + 2 * SESSION_IV_LEN];
    SessionInfo_t *session;
    bool b;
    size_t connCount;
    esp_err_t err;

    err = setDefaultCORS(req);
    if (err != ESP_OK) {
        goto done;
    }

    // Is OPTIONS?
    if (req->method == HTTP_OPTIONS) {
        httpd_resp_set_status(req, HTTPD_204);
        httpd_resp_send(req, nullptr, 0);
        return ESP_OK;
    }

    // Get request IP address
    if (!getClientIpFromRequest(req, &remoteAddr)) {
        ESP_LOGE(TAG, "Failed to get client IP address");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, nullptr);
        return ESP_FAIL;
    }

    // Check rate limit
    if (!rateLimitCheckRequest(&remoteAddr)) {
        httpd_resp_send_custom_err(req, "429 Too Many Requests", "");
        return ESP_FAIL;
    }

    // Read request quey
    rawQuery = parseRequestQuery(serverCtx, req);
    if (!rawQuery) {
        err = ESP_FAIL;
        goto done;
    }

    // Extract parameters from url query
    if (httpd_query_key_value(rawQuery, "token", tokenB64, sizeof(tokenB64)) != ESP_OK ||
        httpd_query_key_value(rawQuery, "wsNonce", wsNonceB64, sizeof(wsNonceB64)) != ESP_OK ||
        httpd_query_key_value(rawQuery, "signature", signatureB64, sizeof(signatureB64)) != ESP_OK
    ) {
error400:
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid parameters");
        err = ESP_FAIL;
        goto done;
    }

    // Validate parameters
    challengeCookieLen = sizeof(challengeCookie);
    wsNonceLen = sizeof(wsNonce);
    signatureLen = sizeof(signature);
    if ((!fromB64(tokenB64, strlen(tokenB64), true, challengeCookie, &challengeCookieLen)) ||
        (!fromB64(wsNonceB64, strlen(wsNonceB64), true, wsNonce, &wsNonceLen)) ||
        (!fromB64(signatureB64, strlen(signatureB64), true, signature, &signatureLen)) ||
        challengeCookieLen != CHALLENGE_COOKIE_SIZE ||
        wsNonceLen != CHALLENGE_NONCE_SIZE ||
        signatureLen != P256_SIGNATURE_SIZE
    ) {
        goto error400;
    }

    // Lookup challenge and check if the user is authenticated
    challenge = challengesFind(challengeCookie, &remoteAddr);
    if (!challenge) {
error401_nc:
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, nullptr);
        err = ESP_FAIL;
        goto done;
    }
    if ((!challenge->verified) ||
        (!constantTimeCompare(challenge->wsNonce, wsNonce, CHALLENGE_NONCE_SIZE))
    ) {
error401:
        challengesRemove(challengeCookie);
        goto error401_nc;
    }

    // th = SHA256("ws-login-v1" || s_nonce || c_nonce || cookie || ws_nonce)
    hash256.init();
    hash256.update("ws-login-v1", 11);
    hash256.update(challenge->serverNonce, sizeof(challenge->serverNonce));
    hash256.update(challenge->clientNonce, sizeof(challenge->clientNonce));
    hash256.update(challengeCookie, sizeof(challengeCookie));
    hash256.update(wsNonce, sizeof(wsNonce));
    hash256.finalize(th);
    if (hash256.error() != ESP_OK) {
        goto error401;
    }

    // Verify signature of th
    err = userVerifySignature(challenge->userId, th, signature);
    if (err != ESP_OK) {
        if (err == MBEDTLS_ERR_ECP_VERIFY_FAILED) {
            goto error401;
        }
error500:
        challengesRemove(challengeCookie);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, ((err == ESP_ERR_NO_MEM) ? "" : nullptr));
        goto done;
    }

    // Build info
    memcpy(info, "mx-iot", 6);
    memcpy(info + 6, challenge->ecdhServerPublicKey, sizeof(challenge->ecdhServerPublicKey));
    memcpy(info + 6 + sizeof(challenge->ecdhServerPublicKey), challenge->ecdhClientPublicKey, sizeof(challenge->ecdhClientPublicKey));

    // Build salt = SHA256("ws-login-v1" || s_nonce || c_nonce || cookie)
    hash256.init();
    hash256.update("ws-login-v1", 11);
    hash256.update(challenge->serverNonce, sizeof(challenge->serverNonce));
    hash256.update(challenge->clientNonce, sizeof(challenge->clientNonce));
    hash256.update(challengeCookie, sizeof(challengeCookie));
    hash256.finalize(salt);
    err = hash256.error();
    if (err != ESP_OK) {
        goto error500;
    }

    // Compute shared secret and derive keys
    err = ecdhKeyPair.loadPrivateKey(challenge->ecdhServerPrivateKey);
    if (err == ESP_OK) {
        err = ecdhKeyPair.loadPublicKey(challenge->ecdhClientPublicKey);
        if (err == ESP_OK) {
            err = ecdhKeyPair.computeSharedSecret(sharedSecret);
        }
    }
    if (err == ESP_OK) {
        err = aesDeriveKey(sharedSecret, AES_KEY_LEN, salt, sizeof(salt), info, sizeof(info), derivedKey, sizeof(derivedKey));
    }
    if (err != ESP_OK) {
        goto error500;
    }

    // Get server context
    serverCtx = (ServerContext_t *)httpd_get_global_user_ctx(req->handle);

    // Create user session
    session = (SessionInfo_t *)malloc(sizeof(SessionInfo_t));
    if (!session) {
        err = ESP_ERR_NO_MEM;
        goto error500;
    }
    memset(session, 0, sizeof(SessionInfo_t));
    do {
        // Generate unique ID
        session->id = nextSessionId.fetch_add(1) & 0x7FFFFFFFUL;
    }
    while (session->id == 0);
    session->sockfd = httpd_req_to_sockfd(req);
    memcpy(&session->addr, &remoteAddr, sizeof(remoteAddr));
    session->userId = challenge->userId;
    session->nextRxCounter = 1;
    session->nextTxCounter = 1;
    memcpy(session->nonce, challenge->wsNonce, sizeof(ChallengeNonce_t));
    memcpy(session->clientAesKey, derivedKey, AES_KEY_LEN);
    memcpy(session->serverAesKey, derivedKey + AES_KEY_LEN, AES_KEY_LEN);
    memcpy(session->clientBaseIV, derivedKey + 2 * AES_KEY_LEN, SESSION_IV_LEN);
    memcpy(session->serverBaseIV, derivedKey + 2 * AES_KEY_LEN + SESSION_IV_LEN, SESSION_IV_LEN);
    err = userIsAdmin(session->userId, &b);
    if (err != ESP_OK) {
        free(session);
        goto error500;
    }
    session->isAdmin = (b) ? 1 : 0;
    err = userMustChangeCredentials(session->userId, &b);
    if (err != ESP_OK) {
        free(session);
        goto error500;
    }
    session->mustChangeCredentials = (b) ? 1 : 0;

    // Bind our internal session to the connection
    httpd_sess_set_ctx(req->handle, session->sockfd, session, destroySessionCtx);

    // Call session start callback
    err = handleSessionStart(session);
    if (err != ESP_OK) {
        goto error500;
    }

    // Look for existing sessions for the same user and close them
    connCount = serverCtx->maxConnectionsCount;
    err = httpd_get_client_list(req->handle, &connCount, serverCtx->clientSocketsBuffer);
    if (err != ESP_OK) {
        goto error500;
    }
    for (size_t i = 0; i < connCount; i++) {
        SessionInfo_t *otherSession;

        // Dont close our own session
        if (serverCtx->clientSocketsBuffer[i] == session->sockfd) {
            continue;
        }
        otherSession = (SessionInfo_t *)httpd_sess_get_ctx(req->handle, serverCtx->clientSocketsBuffer[i]);
        if (otherSession && otherSession->userId == session->userId) {
            ESP_LOGD(TAG, "Closing old session %u for user %u", otherSession->id, otherSession->userId);
            closeWebsocket(req->handle, otherSession->sockfd, WS_CLOSE_GOING_AWAY, "New connection detected");
        }
    }

    // Remove challenge
    challengesRemove(challengeCookie);

    // Reset rate limits for successful access
    rateLimitResetAddress(&remoteAddr);

    // Upgrade to WebSockets
    err = ESP_OK;

done:
    // Cleanup
    memset(derivedKey, 0, sizeof(derivedKey));
    memset(sharedSecret, 0, sizeof(sharedSecret));
    memset(salt, 0, sizeof(salt));
    memset(info, 0, sizeof(info));
    wsNonceLen = challengeCookieLen = 0;
    memset(wsNonce, 0, sizeof(wsNonce));
    memset(challengeCookie, 0, sizeof(challengeCookie));
    memset(wsNonceB64, 0, sizeof(wsNonceB64));
    memset(tokenB64, 0, sizeof(tokenB64));
    return err;
}

static esp_err_t serveWsPacket(httpd_req_t *req)
{
    httpd_ws_frame_t frame;
    uint8_t iv[SESSION_IV_LEN];
    WebSocketPacketHeader_t *hdr;
    size_t dataAndTagLen;
    CommandContext_t commandCtx;
    esp_err_t err;

    commandCtx.serverCtx = (ServerContext_t *)httpd_get_global_user_ctx(req->handle);

    // Get session from session context
    commandCtx.serverHandle = req->handle;
    commandCtx.sockfd = httpd_req_to_sockfd(req);
    commandCtx.session = (SessionInfo_t *)httpd_sess_get_ctx(commandCtx.serverHandle, commandCtx.sockfd);
    if (!commandCtx.session) {
        ESP_LOGD(TAG, "Session not found.");
        closeWebsocket(commandCtx.serverHandle, commandCtx.sockfd, WS_CLOSE_APP_SESSION_NOT_FOUND, nullptr);
        return ESP_FAIL;
    }

    // Read WebSocket packet
    err = readWsPacket(commandCtx.serverCtx, req, &frame);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Unable to read WebSocket packet. Error: %ld.", err);
        return ESP_FAIL;
    }

    // We only accept binary messages
    switch (frame.type) {
        case HTTPD_WS_TYPE_TEXT:
            ESP_LOGD(TAG, "Non binary packet.");
            closeWebsocket(commandCtx.serverHandle, commandCtx.sockfd, WS_CLOSE_UNSUPPORTED_DATA, nullptr);
            return ESP_OK;

        case HTTPD_WS_TYPE_BINARY:
            // The only type we accept
            break;

        default:
            return ESP_OK;
    }

    // Check message size
    if (frame.len <= sizeof(WebSocketPacketHeader_t) + TAG_LEN) {
        ESP_LOGD(TAG, "Short packet.");
        closeWebsocket(commandCtx.serverHandle, commandCtx.sockfd, WS_CLOSE_INVALID_PAYLOAD, nullptr);
        return ESP_OK;
    }
    if (frame.len > sizeof(WebSocketPacketHeader_t) + TAG_LEN + MAX_MSG_SIZE) {
        ESP_LOGD(TAG, "Long packet.");
        closeWebsocket(commandCtx.serverHandle, commandCtx.sockfd, WS_CLOSE_INVALID_PAYLOAD, nullptr);
        return ESP_OK;
    }

    // Extract header and validate version and RX counter (a.k.a. nonce)
    hdr = (WebSocketPacketHeader_t *)frame.payload;
    if (hdr->v != VERSION) {
        ESP_LOGD(TAG, "Unsupported version packet.");
        closeWebsocket(commandCtx.serverHandle, commandCtx.sockfd, WS_CLOSE_INVALID_PAYLOAD, nullptr);
        return ESP_OK;
    }
    commandCtx.rxCounter = be32dec(hdr->counter);
    if (commandCtx.session->nextRxCounter != commandCtx.rxCounter) {
        ESP_LOGD(TAG, "Counter mismatch.");
        closeWebsocket(commandCtx.serverHandle, commandCtx.sockfd, WS_CLOSE_INVALID_PAYLOAD, nullptr);
        return ESP_OK;
    }
    commandCtx.session->nextRxCounter += 1;
    commandCtx.cmd = be16dec(hdr->cmd);
    dataAndTagLen = frame.len - sizeof(WebSocketPacketHeader_t);

    // Build IV
    memcpy(iv, commandCtx.session->clientBaseIV, SESSION_IV_LEN);
    for (size_t i = 0; i < 4; i++) {
        iv[SESSION_IV_LEN-i-1] ^= (uint8_t)((commandCtx.rxCounter >> (i << 3)) & 0xFF);
    }

    // Prepare output for decrypted message
    gbReset(&commandCtx.serverCtx->plaintext, false);
    if (!gbEnsureSize(&commandCtx.serverCtx->plaintext, dataAndTagLen - TAG_LEN)) {
        closeWebsocket(commandCtx.serverHandle, commandCtx.sockfd, WS_CLOSE_INTERNAL_ERROR, nullptr);
        return ESP_OK;
    }

    // Decrypt message
    err = aesDecrypt(commandCtx.session->clientAesKey, sizeof(commandCtx.session->clientAesKey),
                    frame.payload + sizeof(WebSocketPacketHeader_t),
                    dataAndTagLen, iv, sizeof(iv), nullptr, 0, commandCtx.serverCtx->plaintext.buffer);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Unable to decrypt message. Error: %ld.", err);
        closeWebsocket(commandCtx.serverHandle, commandCtx.sockfd, WS_CLOSE_INVALID_PAYLOAD, nullptr);
        return ESP_OK;
    }

    // Check if the only accepted command is to change the credentials
    if (commandCtx.session->mustChangeCredentials != 0 && commandCtx.cmd != CMD_CHANGE_USER_CREDENTIALS) {
        ESP_LOGD(TAG, "User must change the access credentials.");
        closeWebsocket(commandCtx.serverHandle, commandCtx.sockfd, WS_CLOSE_APP_CREDENTIALS_CHANGE_MANDATORY, "User must change the access credentials.");
        return ESP_OK;
    }

    commandCtx.br = br_init(commandCtx.serverCtx->plaintext.buffer, dataAndTagLen - TAG_LEN);
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
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Insufficient privileges", commandCtx->rxCounter);
    }

    // Get user name
    if ((!br_read_str(&commandCtx->br, &name, &nameLen)) || nameLen == 0) {
        ESP_LOGD(TAG, "CREATE USER command: Invalid packet.");
        closeWebsocket(commandCtx->serverHandle, commandCtx->sockfd, WS_CLOSE_INVALID_PAYLOAD, nullptr);
        return ESP_OK;
    }

    // Get the new public key
    if (!br_read_blob(&commandCtx->br, P256_PUBLIC_KEY_SIZE, &publicKey)) {
        ESP_LOGD(TAG, "CREATE USER command: Invalid packet.");
        closeWebsocket(commandCtx->serverHandle, commandCtx->sockfd, WS_CLOSE_INVALID_PAYLOAD, nullptr);
        return ESP_OK;
    }
    memcpy(publicKeyBuf, publicKey, P256_PUBLIC_KEY_SIZE);

    // Check if the user already exists
    if (userCreate(name, nameLen, publicKeyBuf) == 0) {
        ESP_LOGD(TAG, "CREATE USER command: Unable to create new user.");
        return buildAndSendErrorReply(commandCtx, ESP_FAIL, "Unable to create new user", commandCtx->rxCounter);
    }

    // Done
    ESP_LOGD(TAG, "CREATE USER command: User successfully created.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, commandCtx->rxCounter);
}

static esp_err_t handleDeleteUser(CommandContext_t *commandCtx)
{
    const char *name;
    size_t nameLen;
    uint32_t targetUserId;
    bool isAdmin = false;
    int *clientSocketsBuffer;
    size_t connCount;

    if (commandCtx->session->isAdmin == 0) {
        ESP_LOGD(TAG, "DELETE USER command: Insufficient privileges.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Insufficient privileges", commandCtx->rxCounter);
    }

    // Get user name
    if ((!br_read_str(&commandCtx->br, &name, &nameLen)) || nameLen == 0) {
        ESP_LOGD(TAG, "DELETE USER command: Invalid packet.");
        closeWebsocket(commandCtx->serverHandle, commandCtx->sockfd, WS_CLOSE_INVALID_PAYLOAD, nullptr);
        return ESP_OK;
    }

    // Find the user
    targetUserId = userGetID(name, nameLen);
    if (targetUserId == 0 || userIsAdmin(targetUserId, &isAdmin) != ESP_OK) {
        ESP_LOGD(TAG, "DELETE USER command: User not found.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_FOUND, "User not found", commandCtx->rxCounter);
    }

    // Check if the user is admin
    if (isAdmin) {
        ESP_LOGD(TAG, "DELETE USER command: Cannot delete administrator.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Cannot delete admin user", commandCtx->rxCounter);
    }

    // Delete it
    userDestroy(targetUserId);

    // Delete active user sessions
    clientSocketsBuffer = commandCtx->serverCtx->clientSocketsBuffer;
    connCount = commandCtx->serverCtx->maxConnectionsCount;
    if (httpd_get_client_list(commandCtx->serverHandle, &connCount, clientSocketsBuffer) == ESP_OK) {
        for (size_t i = 0; i < connCount; i++) {
            SessionInfo_t *otherSession;

            // Dont close our own session
            if (clientSocketsBuffer[i] == commandCtx->sockfd) {
                continue;
            }

            otherSession = (SessionInfo_t *)httpd_sess_get_ctx(commandCtx->serverHandle, clientSocketsBuffer[i]);
            if (otherSession && otherSession->userId == targetUserId) {
                ESP_LOGD(TAG, "Closing session %u for deleted user %u", otherSession->id, otherSession->userId);
                closeWebsocket(commandCtx->serverHandle, otherSession->sockfd, WS_CLOSE_GOING_AWAY, "User has been deleted");
            }
        }
    }

    // Done
    ESP_LOGD(TAG, "DELETE USER command: User successfully deleted.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, commandCtx->rxCounter);
}

static esp_err_t handleResetUserCredentials(CommandContext_t *commandCtx)
{
    const char *name;
    size_t nameLen;
    uint32_t targetUserId;
    bool targetIsAdmin;
    const uint8_t *publicKey;
    uint8_t publicKeyBuf[P256_PUBLIC_KEY_SIZE];
    int *clientSocketsBuffer;
    size_t connCount;

    if (commandCtx->session->isAdmin == 0) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: Insufficient privileges.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Insufficient privileges", commandCtx->rxCounter);
    }

    // Get user name
    if ((!br_read_str(&commandCtx->br, &name, &nameLen)) || nameLen == 0) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: Invalid packet.");
        closeWebsocket(commandCtx->serverHandle, commandCtx->sockfd, WS_CLOSE_INVALID_PAYLOAD, nullptr);
        return ESP_OK;
    }

    // Get the new public key
    if (!br_read_blob(&commandCtx->br, P256_PUBLIC_KEY_SIZE, &publicKey)) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: Invalid packet.");
        closeWebsocket(commandCtx->serverHandle, commandCtx->sockfd, WS_CLOSE_INVALID_PAYLOAD, nullptr);
        return ESP_OK;
    }
    memcpy(publicKeyBuf, publicKey, P256_PUBLIC_KEY_SIZE);

    // Find the user
    targetUserId = userGetID(name, nameLen);
    if (targetUserId == 0) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: User not found.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_FOUND, "User not found", commandCtx->rxCounter);
    }

    // Check if the user is the same than us
    if (commandCtx->session->userId == targetUserId) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: Cannot reset own credentials.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Cannot reset own credentials", commandCtx->rxCounter);
    }

    // Check if the target user is an admin
    if (userIsAdmin(targetUserId, &targetIsAdmin) != ESP_OK || targetIsAdmin) {
        ESP_LOGD(TAG, "RESET USER CREDENTIALS command: Cannot reset user credentials.");
        return buildAndSendErrorReply(commandCtx, ESP_ERR_NOT_ALLOWED, "Cannot reset user credentials", commandCtx->rxCounter);
    }

    // Change the user public key
    if (userChangeCredentials(targetUserId, commandCtx->session->userId, publicKeyBuf) != ESP_OK) {
        ESP_LOGD(TAG, "RESET USER PASSWORD command: Unable to reset user credentials.");
        return buildAndSendErrorReply(commandCtx, ESP_FAIL, "Unable to reset user credentials", commandCtx->rxCounter);
    }

    // Delete active target user sessions
    clientSocketsBuffer = commandCtx->serverCtx->clientSocketsBuffer;
    connCount = commandCtx->serverCtx->maxConnectionsCount;
    if (httpd_get_client_list(commandCtx->serverHandle, &connCount, clientSocketsBuffer) == ESP_OK) {
        for (size_t i = 0; i < connCount; i++) {
            SessionInfo_t *otherSession;

            // Don't close our own session
            if (clientSocketsBuffer[i] == commandCtx->sockfd) {
                continue;
            }

            otherSession = (SessionInfo_t *)httpd_sess_get_ctx(commandCtx->serverHandle, clientSocketsBuffer[i]);
            if (otherSession && otherSession->userId == targetUserId) {
                ESP_LOGD(TAG, "Closing session %u for deleted user %u", otherSession->id, otherSession->userId);
                closeWebsocket(commandCtx->serverHandle, otherSession->sockfd, WS_CLOSE_GOING_AWAY, "User credentials has been reset");
            }
        }
    }

    // Done
    ESP_LOGD(TAG, "RESET USER PASSWORD command: User password successfully changed.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, commandCtx->rxCounter);
}

static esp_err_t handleChangeUserCredentials(CommandContext_t *commandCtx)
{
    const uint8_t *signature;
    const uint8_t *publicKey;
    uint8_t publicKeyBuf[P256_PUBLIC_KEY_SIZE];
    Sha256 hash256;
    uint8_t th[SHA256_SIZE];
    uint8_t signatureToVerify[P256_SIGNATURE_SIZE];

    // Get the signature validation for the old key
    if (!br_read_blob(&commandCtx->br, P256_SIGNATURE_SIZE, &signature)) {
        ESP_LOGD(TAG, "CHANGE PASSWORD command: Invalid packet.");
        closeWebsocket(commandCtx->serverHandle, commandCtx->sockfd, WS_CLOSE_INVALID_PAYLOAD, nullptr);
        return ESP_OK;
    }

    // Get the new public key
    if (!br_read_blob(&commandCtx->br, P256_PUBLIC_KEY_SIZE, &publicKey)) {
        ESP_LOGD(TAG, "CHANGE PASSWORD command: Invalid packet.");
        closeWebsocket(commandCtx->serverHandle, commandCtx->sockfd, WS_CLOSE_INVALID_PAYLOAD, nullptr);
        return ESP_OK;
    }
    memcpy(publicKeyBuf, publicKey, P256_PUBLIC_KEY_SIZE);

    // th = SHA256("ws-chgcreds-v1" || publicKey || ws_nonce)
    hash256.init();
    hash256.update("ws-chgcreds-v1", 14);
    hash256.update(publicKeyBuf, P256_PUBLIC_KEY_SIZE);
    hash256.update(commandCtx->session->nonce, sizeof(commandCtx->session->nonce));
    hash256.finalize(th);
    if (hash256.error() != ESP_OK) {
error_validation_failed:
        ESP_LOGD(TAG, "CHANGE PASSWORD command: Validation failed.");
        if (commandCtx->session->credentialsChangeAttempts < 2) {
            commandCtx->session->credentialsChangeAttempts += 1;
            return buildAndSendErrorReply(commandCtx, ESP_FAIL, "Validation failed", commandCtx->rxCounter);
        }
        closeWebsocket(commandCtx->serverHandle, commandCtx->sockfd, WS_CLOSE_POLICY_VIOLATION, nullptr);
        return ESP_OK;
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
        return buildAndSendErrorReply(commandCtx, ESP_FAIL, "Unable to change user credentials", commandCtx->rxCounter);
    }

    commandCtx->session->mustChangeCredentials = 0;

    // Done
    ESP_LOGD(TAG, "CHANGE PASSWORD command: Credentials successfully changed.");
    return buildAndSendErrorReply(commandCtx, ESP_OK, nullptr, commandCtx->rxCounter);
}

static esp_err_t handleCustomCommand(CommandContext_t *commandCtx)
{
    IotCommEventCustomCommand_t eventData;

    // Populate event data
    eventData.sessionId = commandCtx->session->id;
    eventData.userId = commandCtx->session->userId;
    eventData.userIsAdmin = (commandCtx->session->isAdmin != 0) ? true : false;
    eventData.cmd = commandCtx->cmd;
    eventData.data = commandCtx->br.ptr;
    eventData.dataLen = commandCtx->br.len;

    auto replyImpl = [commandCtx](const uint8_t *reply, size_t replyLen) -> bool {
        esp_err_t err;

        err = buildAndSendReply(commandCtx, reply, replyLen, commandCtx->rxCounter);
        return !!(err == ESP_OK);
    };
    eventData.reply = replyImpl;

    auto replywithErrorImpl = [commandCtx](uint32_t code, const char *message) -> bool {
        esp_err_t err;

        err = buildAndSendErrorReply(commandCtx, code, message, commandCtx->rxCounter);
        return !!(err == ESP_OK);
    };
    eventData.replyWithError = replywithErrorImpl;

    auto closeImpl = [commandCtx](uint16_t reason, const char *message) -> void {
        closeWebsocket(commandCtx->serverHandle, commandCtx->sockfd, reason, message);
    };
    eventData.close = closeImpl;

    auto getUserDataImpl = [commandCtx]() -> void* {
        return commandCtx->session->userData;
    };
    eventData.getUserData = getUserDataImpl;

    // Raise event
    handler(IotCommEventCustomCommand, &eventData);

    // Done
    return ESP_OK;
}

static esp_err_t handleSessionStart(SessionInfo_t *session)
{
    IotCommEventSessionStart_t eventData;
    esp_err_t err = ESP_OK;

    // Populate event data
    eventData.sessionId = session->id;
    eventData.userId = session->userId;
    eventData.userIsAdmin = (session->isAdmin != 0) ? true : false;

    auto setErrorImpl = [&err](esp_err_t _err) -> void {
        err = _err;
    };
    eventData.setError = setErrorImpl;

    auto setUserDataImpl = [session](const void *ptr, IotCommUserDataFreeFunc_t freeFn) -> void {
        session->userData = (void *)ptr;
        session->userDataFreeFn = freeFn;
    };
    eventData.setUserData = setUserDataImpl;

    // Raise event
    handler(IotCommEventSessionStart, &eventData);

    // Done
    return err;
}

static void handleSessionEnd(SessionInfo_t *session)
{
    IotCommEventSessionEnd_t eventData;

    // Populate event data
    eventData.sessionId = session->id;
    eventData.userId = session->userId;

    auto getUserDataImpl = [session]() -> void* {
        return session->userData;
    };
    eventData.getUserData = getUserDataImpl;

    // Raise event
    handler(IotCommEventSessionEnd, &eventData);
}

static esp_err_t buildAndSendReply(CommandContext_t *commandCtx, const uint8_t *plaintext, size_t plaintextLen, uint32_t replyCounter)
{
    GrowableBuffer_t *outBuf = &commandCtx->serverCtx->ciphertext;
    WebSocketPacketHeader_t *hdr;
    uint32_t nextTxCounter;
    httpd_ws_frame_t frame;
    uint8_t iv[SESSION_IV_LEN];
    esp_err_t err;

    // Prepare output for encrypted message
    gbReset(outBuf, false);
    if (!gbEnsureSize(outBuf, sizeof(WebSocketPacketHeader_t) + plaintextLen + TAG_LEN)) {
        closeWebsocket(commandCtx->serverHandle, commandCtx->sockfd, WS_CLOSE_INTERNAL_ERROR, nullptr);
        return ESP_OK;
    }

    // Header
    hdr = (WebSocketPacketHeader_t *)outBuf->buffer;
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
    err = aesEncrypt(commandCtx->session->serverAesKey, sizeof(commandCtx->session->serverAesKey), plaintext, plaintextLen,
                    iv, SESSION_IV_LEN, nullptr, 0, outBuf->buffer + sizeof(WebSocketPacketHeader_t));
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Unable to encrypt message. Error: %ld.", err);
        closeWebsocket(commandCtx->serverHandle, commandCtx->sockfd, WS_CLOSE_INTERNAL_ERROR, nullptr);
        return ESP_OK;
    }

    // Send it
    memset(&frame, 0, sizeof(frame));
    frame.final = true;
    frame.type = HTTPD_WS_TYPE_BINARY;
    frame.len = sizeof(WebSocketPacketHeader_t) + plaintextLen + TAG_LEN;
    frame.payload = outBuf->buffer;

    err = httpd_ws_send_frame_async(commandCtx->serverHandle, commandCtx->sockfd, &frame);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Unable to deliver message. Error: %ld.", err);
        closeWebsocket(commandCtx->serverHandle, commandCtx->sockfd, WS_CLOSE_INTERNAL_ERROR, nullptr);
        return ESP_OK;
    }

    // Increment TX counter
    commandCtx->session->nextTxCounter += 1;

    // Done
    return ESP_OK;
}

static esp_err_t buildAndSendErrorReply(CommandContext_t *commandCtx, uint32_t code, const char *message, uint32_t replyCounter)
{
    GrowableBuffer_t *outBuf = &commandCtx->serverCtx->plaintext;
    void *ptr;

    gbReset(outBuf, false);

    ptr = gbReserve(outBuf, sizeof(uint32_t));
    if (!ptr) {
        return false;
    }
    be32enc(ptr, code);

    if (message && *message != 0) {
        size_t msgLen = strlen(message);

        if (!gbAdd(outBuf, message, msgLen)) {
            return false;
        }
    }
    if (!gbAdd(outBuf, "\0", 1)) {
        return false;
    }
    return buildAndSendReply(commandCtx, outBuf->buffer, outBuf->used, replyCounter);
}

static const char *parseRequestBody(ServerContext_t *serverCtx, httpd_req_t *req, size_t *rawBodyLen)
{
    char *rawBody;
    size_t curLen;
    int received;

    *rawBodyLen = 0;
    if (req->content_len > MAX_BODY_SIZE) {
        httpd_resp_send_err(req, HTTPD_413_CONTENT_TOO_LARGE, nullptr);
        return nullptr;
    }

    gbReset(&serverCtx->plaintext, false);
    rawBody = (char *)gbReserve(&serverCtx->plaintext, req->content_len + 1);
    if (!rawBody) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to allocate memory");
        return nullptr;
    }

    for (curLen = 0; curLen < req->content_len; curLen += (size_t)received) {
        received = httpd_req_recv(req, rawBody + curLen, req->content_len - curLen);
        if (received <= 0) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to get request body");
            return nullptr;
        }
    }

    // Done
    *rawBodyLen = req->content_len;
    return rawBody;
}

static const char *parseRequestQuery(ServerContext_t *serverCtx, httpd_req_t *req)
{
    char *rawQuery;
    size_t queryLen;

    queryLen = httpd_req_get_url_query_len(req);
    if (queryLen > MAX_QUERY_SIZE) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Query too long");
        return nullptr;
    }

    gbReset(&serverCtx->plaintext, false);
    rawQuery = (char *)gbReserve(&serverCtx->plaintext, queryLen + 1);
    if (!rawQuery) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to allocate memory");
        return nullptr;
    }

    if (queryLen > 1) {
        if (httpd_req_get_url_query_str(req, rawQuery, queryLen + 1) != ESP_OK) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to get request query");
            return nullptr;
        }
    }
    rawQuery[queryLen] = 0;

    // Done
    return rawQuery;
}

static esp_err_t setDefaultCORS(httpd_req_t *req)
{
    esp_err_t err;

    // NOTE: No need to save values until response is sent because they are constant values.
    err = httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    if (err == ESP_OK) {
        err = httpd_resp_set_hdr(req, "Vary", "Origin");
    }
    if (err == ESP_OK) {
        err = httpd_resp_set_hdr(req, "Access-Control-Allow-Credentials", "true");
    }
    if (err == ESP_OK && req->method == HTTP_OPTIONS) {
        err = httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        if (err == ESP_OK) {
            err = httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type, Authorization");
        }
    }
    return err;
}

static bool getClientIpFromRequest(httpd_req_t *req, IPAddress_t *out)
{
    char hdr[256];
    size_t len;
    esp_err_t err;

    err = httpd_req_get_hdr_value_str(req, "Forwarded", hdr, sizeof(hdr));
    if (err == ESP_OK && hdr[0] != 0) {
        hdr[sizeof(hdr) - 1] = '\0';

        const char *p = hdr;
        const char *pEnd = hdr + sizeof(hdr);
        while (p < pEnd && (p = strcasestr(p, "for=")) != nullptr) {
            p += 4; // skip "for="

            len = 0;
            while (p[len] != 0 && p[len] != ',' && p + len < pEnd - 1) {
                len++;
            }

            if (parseIP(out, p, len)) {
                return true;
            }

            p += len;
        }
    }

    err = httpd_req_get_hdr_value_str(req, "X-Forwarded-For", hdr, sizeof(hdr));
    if (err == ESP_OK && hdr[0] != 0) {
        len = 0;
        while (hdr[len] != 0 && hdr[len] != ',' && len < sizeof(hdr) - 1) {
            len++;
        }

        if (parseIP(out, hdr, len)) {
            return true;
        }
    }

    err = httpd_req_get_hdr_value_str(req, "X-Real-IP", hdr, sizeof(hdr));
    if (err == ESP_OK && hdr[0] != 0) {
        hdr[sizeof(hdr) - 1] = '\0';
        if (parseIP(out, hdr)) {
            return true;
        }
    }

    if (getIpFromPeer(httpd_req_to_sockfd(req), out)) {
        return true;
    }

    // We were unable to determine the IP
    return false;
}

static bool getIpFromPeer(int sockfd, IPAddress_t *out)
{
    struct sockaddr_storage addr;
    socklen_t addrLen = sizeof(addr);

    if (getpeername(sockfd, (struct sockaddr *)&addr, &addrLen) == 0) {
        switch (addr.ss_family) {
            case AF_INET:
                parseIPv4(out, (const struct sockaddr_in *)&addr);
                return true;

            case AF_INET6:
                parseIPv6(out, (const struct sockaddr_in6 *)&addr);
                return true;
        }
    }
    return false;
}

static void destroyServerCtx(void *ctx)
{
    if (ctx) {
        ServerContext_t *serverCtx = (ServerContext_t *)ctx;

        gbReset(&serverCtx->plaintext, true);
        gbReset(&serverCtx->ciphertext, true);
        free(serverCtx->clientSocketsBuffer);
        free(serverCtx);
    }
}

static void destroySessionCtx(void *ctx)
{
    if (ctx) {
        SessionInfo_t *session = (SessionInfo_t *)ctx;

        // Call session end callback
        handleSessionEnd(session);

        // Free user data
        if (session->userData) {
            if (session->userDataFreeFn) {
                session->userDataFreeFn(session->userData);
            }
            else {
                free(session->userData);
            }
        }

        memset(session, 0, sizeof(SessionInfo_t));
        free(session);
    }
}

static esp_err_t readWsPacket(ServerContext_t *serverCtx, httpd_req_t *req, httpd_ws_frame_t *frame)
{
    esp_err_t err;

    memset(frame, 0, sizeof(httpd_ws_frame_t));
    frame->type = HTTPD_WS_TYPE_TEXT;
    err = httpd_ws_recv_frame(req, frame, 0);
    if (err != ESP_OK) {
        return err;
    }
    if (frame->len > 0) {
        gbReset(&serverCtx->ciphertext, false);
        frame->payload = (uint8_t *)gbReserve(&serverCtx->ciphertext, frame->len);
        if (!frame->payload) {
            return ESP_ERR_NO_MEM;
        }

        err = httpd_ws_recv_frame(req, frame, frame->len);
        if (err != ESP_OK) {
            return err;
        }
    }
    return ESP_OK;
}

static void closeWebsocket(httpd_handle_t serverHandle, int sockfd, uint16_t code, const char *reason)
{
    httpd_ws_frame_t frame;
    uint8_t buf[1024];

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

    httpd_ws_send_frame_async(serverHandle, sockfd, &frame);

    httpd_sess_trigger_close(serverHandle, sockfd);
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
