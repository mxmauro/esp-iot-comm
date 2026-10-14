#include <unity.h>
#include <iot_comm/iot_comm.h>
#include <iot_comm/crypto/aes.h>
#include <iot_comm/crypto/hkdf.h>
#include <iot_comm/crypto/p256.h>
#include <iot_comm/crypto/sha.h>
#include <iot_comm/crypto/utils.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <convert.h>
#include <endian.h>
#include <lwip/inet.h>
#include <lwip/sockets.h>
#include <stdlib.h>
#include <string.h>

// -----------------------------------------------------------------------------

#define TEST_COMMAND_HTTP_PORT 18082
#define TEST_COMMAND_UDP_PORT  18083
#define TEST_UDP_COMMAND       0x0042

#define TEST_CMD_CREATE_USER             0x7FF1
#define TEST_CMD_CHANGE_USER_CREDENTIALS 0x7FF4
#define TEST_CMD_UDP_OPEN                0x7FF8

// -----------------------------------------------------------------------------

typedef struct CommandTestStorage_s {
    uint8_t* data[3];
    size_t   len[3];
} CommandTestStorage_t;

typedef struct CommandTestContext_s {
    P256KeyPair_t       rootKey;
    CommandTestStorage_t storage;
    SemaphoreHandle_t   done;
    SemaphoreHandle_t   udpReceived;
    SemaphoreHandle_t   sessionReady;
    SemaphoreHandle_t   clientRelease;
    esp_err_t           clientErr;
    bool                receivedUdpCommand;
    bool                udpRepliesRejected;
} CommandTestContext_t;

typedef struct CommandTestClient_s {
    int          socketFd;
    P256KeyPair_t ecdhKey;
    AesContext_t clientAes;
    AesContext_t serverAes;
    uint8_t      clientPublicKey[P256_PUBLIC_KEY_SIZE];
    uint8_t      clientNonce[16];
    uint8_t      serverNonce[16];
    uint8_t      token[12];
    uint8_t      wsNonce[16];
    uint8_t      masterKey[32];
    uint8_t      clientBaseIv[12];
    uint8_t      serverBaseIv[12];
    uint64_t     nextClientCounter;
    uint64_t     nextServerCounter;
} CommandTestClient_t;

// -----------------------------------------------------------------------------

static esp_err_t commandTestLoad(IotCommStorageItemType_t type, void* dest, size_t destLen, void* ctx);
static esp_err_t commandTestSave(IotCommStorageItemType_t type, const void* data, size_t dataLen, void* ctx);
static esp_err_t commandTestRootKey(uint8_t publicKey[P256_PUBLIC_KEY_SIZE], void* ctx);
static void commandTestEventHandler(IotCommEvent_t* event);
static bool commandTestInit(CommandTestContext_t* testCtx);
static void commandTestDone(CommandTestContext_t* testCtx);
static bool commandTestSendAll(int socketFd, const void* data, size_t len);
static bool commandTestRecvAll(int socketFd, void* data, size_t len);
static bool commandTestReadHttp(int socketFd, char* response, size_t responseSize, char** body);
static bool commandTestPost(int socketFd, const char* path, const char* body, char* response, size_t responseSize, char** responseBody);
static bool commandTestJsonString(const char* json, const char* name, char* value, size_t valueSize);
static bool commandTestHash(uint8_t hash[SHA256_SIZE], const uint8_t* const* parts, const size_t* lens, size_t count);
static bool commandTestLoginSalt(const CommandTestClient_t* client, const uint8_t* extra, size_t extraLen, uint8_t salt[SHA256_SIZE]);
static void commandTestIv(const uint8_t baseIv[12], uint64_t counter, uint8_t iv[12]);
static bool commandTestSendWs(int socketFd, const uint8_t* payload, size_t payloadLen);
static bool commandTestRecvWs(int socketFd, uint8_t* payload, size_t* payloadLen);
static bool commandTestClientOpen(CommandTestClient_t* client, CommandTestContext_t* testCtx);
static void commandTestClientClose(CommandTestClient_t* client);
static bool commandTestCommand(CommandTestClient_t* client, uint16_t cmd, const uint8_t* request, size_t requestLen, uint8_t* reply,
                               size_t* replyLen);
static bool commandTestChangeRoot(CommandTestClient_t* client, CommandTestContext_t* testCtx);
static bool commandTestCreateUser(CommandTestClient_t* client);
static bool commandTestOpenUdp(CommandTestClient_t* client, uint16_t* port, uint32_t* id, uint8_t key[32], uint8_t baseIv[12]);
static bool commandTestSendUdp(int socketFd, uint16_t port, uint32_t id, const uint8_t key[32], const uint8_t baseIv[12], uint16_t cmd,
                               uint64_t counter, const uint8_t* payload, size_t payloadLen);
static void commandTestClientTask(void* arg);

// -----------------------------------------------------------------------------

TEST_CASE("IoT-Comm processes commands and stops a live loopback session", "[iot_comm][integration]")
{
    CommandTestContext_t testCtx = {};
    bool initialized;
    bool sessionReady;
    bool completed;
    bool receivedUdpCommand;
    bool udpRepliesRejected;
    esp_err_t clientErr;

    initialized = commandTestInit(&testCtx);
    if (!initialized)
    {
        commandTestDone(&testCtx);
        TEST_FAIL_MESSAGE("Failed to initialize the loopback command test.");
    }
    if (xTaskCreate(commandTestClientTask, "iotcomm-cmd", 12288, &testCtx, 5, nullptr) != pdPASS)
    {
        commandTestDone(&testCtx);
        TEST_FAIL_MESSAGE("Failed to create the loopback client task.");
    }
    sessionReady = xSemaphoreTake(testCtx.sessionReady, pdMS_TO_TICKS(15000)) == pdTRUE;
    if (sessionReady)
    {
        iotCommStopServer();
    }
    xSemaphoreGive(testCtx.clientRelease);
    completed = xSemaphoreTake(testCtx.done, pdMS_TO_TICKS(15000)) == pdTRUE;
    clientErr = testCtx.clientErr;
    receivedUdpCommand = testCtx.receivedUdpCommand;
    udpRepliesRejected = testCtx.udpRepliesRejected;
    commandTestDone(&testCtx);
    TEST_ASSERT_TRUE(sessionReady);
    TEST_ASSERT_TRUE(completed);
    TEST_ASSERT_EQUAL(ESP_OK, clientErr);
    TEST_ASSERT_TRUE(receivedUdpCommand);
    TEST_ASSERT_TRUE(udpRepliesRejected);
}

// -----------------------------------------------------------------------------

static esp_err_t commandTestLoad(IotCommStorageItemType_t type, void* dest, size_t destLen, void* ctx)
{
    CommandTestStorage_t* storage = &static_cast<CommandTestContext_t*>(ctx)->storage;

    if (type >= 3)
    {
        return ESP_ERR_INVALID_ARG;
    }
    if (!storage->data[type])
    {
        return ESP_ERR_NOT_FOUND;
    }
    if (storage->len[type] != destLen)
    {
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(dest, storage->data[type], destLen);
    return ESP_OK;
}

static esp_err_t commandTestSave(IotCommStorageItemType_t type, const void* data, size_t dataLen, void* ctx)
{
    CommandTestStorage_t* storage = &static_cast<CommandTestContext_t*>(ctx)->storage;
    uint8_t* copy;

    if (type >= 3)
    {
        return ESP_ERR_INVALID_ARG;
    }
    copy = static_cast<uint8_t*>(malloc(dataLen));
    if (!copy)
    {
        return ESP_ERR_NO_MEM;
    }
    memcpy(copy, data, dataLen);
    if (storage->data[type])
    {
        memset(storage->data[type], 0, storage->len[type]);
        free(storage->data[type]);
    }
    storage->data[type] = copy;
    storage->len[type] = dataLen;
    return ESP_OK;
}

static esp_err_t commandTestRootKey(uint8_t publicKey[P256_PUBLIC_KEY_SIZE], void* ctx)
{
    return p256SavePublicKey(&static_cast<CommandTestContext_t*>(ctx)->rootKey, publicKey);
}

static void commandTestEventHandler(IotCommEvent_t* event)
{
    CommandTestContext_t* testCtx = static_cast<CommandTestContext_t*>(event->ctx);

    if (event->eventType == IotCommEventTypeCustomCommand && event->command->transportType == IotCommTransportTypeUDP &&
        event->command->cmd == TEST_UDP_COMMAND && event->command->dataLen == 3)
    {
        if (memcmp(event->command->data, "old", 3) == 0)
        {
            xSemaphoreGive(testCtx->udpReceived);
        }
        else if (memcmp(event->command->data, "udp", 3) == 0)
        {
            esp_err_t replyErr = iotCommEventReply(event->sessionHandle, nullptr, 0);
            esp_err_t errorReplyErr = iotCommEventReplyWithError(event->sessionHandle, ESP_FAIL, "unsupported");

            testCtx->receivedUdpCommand = true;
            testCtx->udpRepliesRejected = replyErr == ESP_ERR_NOT_ALLOWED && errorReplyErr == ESP_ERR_NOT_ALLOWED;
            xSemaphoreGive(testCtx->udpReceived);
        }
    }
}

static bool commandTestInit(CommandTestContext_t* testCtx)
{
    IotCommConfig_t config = iotCommDefaultConfig();
    IotCommServerConfig_t serverConfig = iotCommDefaultServerConfig();
    esp_err_t err;

    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE)
    {
        return false;
    }
    err = esp_netif_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE)
    {
        return false;
    }
    p256KeyPairInit(&testCtx->rootKey);
    if (ecdsaGeneratePair(&testCtx->rootKey) != ESP_OK)
    {
        return false;
    }
    vTaskDelay(1);
    testCtx->done = xSemaphoreCreateBinary();
    testCtx->udpReceived = xSemaphoreCreateBinary();
    testCtx->sessionReady = xSemaphoreCreateBinary();
    testCtx->clientRelease = xSemaphoreCreateBinary();
    if (!testCtx->done || !testCtx->udpReceived || !testCtx->sessionReady || !testCtx->clientRelease)
    {
        commandTestDone(testCtx);
        return false;
    }
    config.handler = commandTestEventHandler;
    config.handlerCtx = testCtx;
    config.rootKey.cb = commandTestRootKey;
    config.rootKey.ctx = testCtx;
    config.storage.load = commandTestLoad;
    config.storage.save = commandTestSave;
    config.storage.ctx = testCtx;
    serverConfig.listenPort = TEST_COMMAND_HTTP_PORT;
    serverConfig.udpListenPort = TEST_COMMAND_UDP_PORT;
    if (iotCommInit(&config) != ESP_OK || iotCommStartServer(&serverConfig) != ESP_OK)
    {
        commandTestDone(testCtx);
        return false;
    }
    return true;
}

static void commandTestDone(CommandTestContext_t* testCtx)
{
    iotCommStopServer();
    iotCommDeinit();
    if (testCtx->done)
    {
        vSemaphoreDelete(testCtx->done);
    }
    if (testCtx->udpReceived)
    {
        vSemaphoreDelete(testCtx->udpReceived);
    }
    if (testCtx->sessionReady)
    {
        vSemaphoreDelete(testCtx->sessionReady);
    }
    if (testCtx->clientRelease)
    {
        vSemaphoreDelete(testCtx->clientRelease);
    }
    p256KeyPairDone(&testCtx->rootKey);
    for (size_t i = 0; i < 3; i++)
    {
        if (testCtx->storage.data[i])
        {
            memset(testCtx->storage.data[i], 0, testCtx->storage.len[i]);
            free(testCtx->storage.data[i]);
        }
    }
    memset(testCtx, 0, sizeof(*testCtx));
}

static bool commandTestSendAll(int socketFd, const void* data, size_t len)
{
    const uint8_t* ptr = static_cast<const uint8_t*>(data);

    while (len > 0)
    {
        int sent = send(socketFd, ptr, len, 0);

        if (sent <= 0)
        {
            return false;
        }
        ptr += sent;
        len -= static_cast<size_t>(sent);
    }
    return true;
}

static bool commandTestRecvAll(int socketFd, void* data, size_t len)
{
    uint8_t* ptr = static_cast<uint8_t*>(data);

    while (len > 0)
    {
        int received = recv(socketFd, ptr, len, 0);

        if (received <= 0)
        {
            return false;
        }
        ptr += received;
        len -= static_cast<size_t>(received);
    }
    return true;
}

static bool commandTestReadHttp(int socketFd, char* response, size_t responseSize, char** body)
{
    size_t used = 0;

    while (used < responseSize - 1)
    {
        char* headerEnd;
        char* contentLength;
        size_t bodyLen = 0;
        int received = recv(socketFd, response + used, responseSize - 1 - used, 0);

        if (received <= 0)
        {
            return false;
        }
        used += static_cast<size_t>(received);
        response[used] = 0;
        headerEnd = strstr(response, "\r\n\r\n");
        if (!headerEnd)
        {
            continue;
        }
        contentLength = strstr(response, "Content-Length: ");
        if (contentLength)
        {
            bodyLen = strtoul(contentLength + strlen("Content-Length: "), nullptr, 10);
        }
        *body = headerEnd + 4;
        if (used >= static_cast<size_t>(*body - response) + bodyLen)
        {
            return strncmp(response, "HTTP/1.1 200", 12) == 0 || strncmp(response, "HTTP/1.1 101", 12) == 0;
        }
    }
    return false;
}

static bool commandTestPost(int socketFd, const char* path, const char* body, char* response, size_t responseSize, char** responseBody)
{
    char request[768];
    int len = snprintf(request, sizeof(request),
                       "POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: %u\r\n\r\n%s", path,
                       static_cast<unsigned>(strlen(body)), body);

    return len > 0 && static_cast<size_t>(len) < sizeof(request) && commandTestSendAll(socketFd, request, len) &&
           commandTestReadHttp(socketFd, response, responseSize, responseBody);
}

static bool commandTestJsonString(const char* json, const char* name, char* value, size_t valueSize)
{
    char pattern[48];
    const char* start;
    const char* end;
    int patternLen = snprintf(pattern, sizeof(pattern), "\"%s\":\"", name);

    if (patternLen <= 0 || static_cast<size_t>(patternLen) >= sizeof(pattern))
    {
        return false;
    }
    start = strstr(json, pattern);
    if (!start)
    {
        return false;
    }
    start += patternLen;
    end = strchr(start, '\"');
    if (!end || static_cast<size_t>(end - start) >= valueSize)
    {
        return false;
    }
    memcpy(value, start, static_cast<size_t>(end - start));
    value[end - start] = 0;
    return true;
}

static bool commandTestHash(uint8_t hash[SHA256_SIZE], const uint8_t* const* parts, const size_t* lens, size_t count)
{
    Sha256Context_t sha;
    esp_err_t err;

    sha256Init(&sha);
    err = sha256Start(&sha);
    for (size_t i = 0; err == ESP_OK && i < count; i++)
    {
        if (lens[i] > 0)
        {
            err = sha256Update(&sha, parts[i], lens[i]);
        }
    }
    if (err == ESP_OK)
    {
        err = sha256Finish(&sha, hash);
    }
    sha256Done(&sha);
    return err == ESP_OK;
}

static bool commandTestLoginSalt(const CommandTestClient_t* client, const uint8_t* extra, size_t extraLen, uint8_t salt[SHA256_SIZE])
{
    static const uint8_t label[] = "ws-login-v1";
    const uint8_t* parts[] = {label, client->serverNonce, client->clientNonce, client->token, extra};
    const size_t lens[] = {sizeof(label) - 1, 16, 16, 12, extraLen};

    return commandTestHash(salt, parts, lens, sizeof(parts) / sizeof(parts[0]));
}

static void commandTestIv(const uint8_t baseIv[12], uint64_t counter, uint8_t iv[12])
{
    memcpy(iv, baseIv, 12);
    for (size_t i = 0; i < 8; i++)
    {
        iv[11 - i] ^= static_cast<uint8_t>(counter >> (i * 8));
    }
}

static bool commandTestSendWs(int socketFd, const uint8_t* payload, size_t payloadLen)
{
    uint8_t header[8];
    uint8_t masked[512];
    uint8_t mask[4];
    size_t headerLen = 0;

    if (payloadLen > sizeof(masked) || randomize(mask, sizeof(mask)) != ESP_OK)
    {
        return false;
    }
    header[headerLen++] = 0x82;
    if (payloadLen <= 125)
    {
        header[headerLen++] = 0x80 | static_cast<uint8_t>(payloadLen);
    }
    else
    {
        header[headerLen++] = 0xFE;
        header[headerLen++] = static_cast<uint8_t>(payloadLen >> 8);
        header[headerLen++] = static_cast<uint8_t>(payloadLen);
    }
    memcpy(header + headerLen, mask, sizeof(mask));
    headerLen += sizeof(mask);
    for (size_t i = 0; i < payloadLen; i++)
    {
        masked[i] = payload[i] ^ mask[i % sizeof(mask)];
    }
    return commandTestSendAll(socketFd, header, headerLen) && commandTestSendAll(socketFd, masked, payloadLen);
}

static bool commandTestRecvWs(int socketFd, uint8_t* payload, size_t* payloadLen)
{
    uint8_t header[2];
    uint8_t ext[2];
    size_t len;

    if (!commandTestRecvAll(socketFd, header, sizeof(header)) || header[0] != 0x82 || (header[1] & 0x80) != 0)
    {
        return false;
    }
    len = header[1];
    if (len == 126)
    {
        if (!commandTestRecvAll(socketFd, ext, sizeof(ext)))
        {
            return false;
        }
        len = (static_cast<size_t>(ext[0]) << 8) | ext[1];
    }
    if (len > *payloadLen || len == 127)
    {
        return false;
    }
    if (!commandTestRecvAll(socketFd, payload, len))
    {
        return false;
    }
    *payloadLen = len;
    return true;
}

static bool commandTestClientOpen(CommandTestClient_t* client, CommandTestContext_t* testCtx)
{
    uint8_t serverKey[P256_PUBLIC_KEY_SIZE];
    uint8_t sharedSecret[32];
    uint8_t authKey[32];
    uint8_t authIv[12];
    uint8_t authNonce[16];
    uint8_t signature[P256_SIGNATURE_SIZE];
    uint8_t hash[SHA256_SIZE];
    uint8_t salt[SHA256_SIZE];
    uint8_t encryptedAuth[320];
    uint8_t derived[88];
    char clientNonceB64[32];
    char clientKeyB64[96];
    char tokenB64[32];
    char serverNonceB64[32];
    char serverKeyB64[96];
    char authNonceB64[32];
    char signatureB64[128];
    char authIvB64[32];
    char encryptedB64[512];
    char wsNonceB64[32];
    char ticketB64[32];
    char body[640];
    char response[1024];
    char request[320];
    char* responseBody;
    struct sockaddr_in addr = {};
    struct timeval timeout = {};
    size_t len;
    int textLen;
    bool ok = false;

    memset(client, 0, sizeof(*client));
    client->socketFd = -1;
    p256KeyPairInit(&client->ecdhKey);
    aesInit(&client->clientAes);
    aesInit(&client->serverAes);
    if (randomize(client->clientNonce, sizeof(client->clientNonce)) != ESP_OK || ecdhGeneratePair(&client->ecdhKey) != ESP_OK ||
        p256SavePublicKey(&client->ecdhKey, client->clientPublicKey) != ESP_OK)
    {
        goto done;
    }
    len = sizeof(clientNonceB64) - 1;
    if (!toB64(client->clientNonce, sizeof(client->clientNonce), false, clientNonceB64, &len))
    {
        goto done;
    }
    clientNonceB64[len] = 0;
    len = sizeof(clientKeyB64) - 1;
    if (!toB64(client->clientPublicKey, sizeof(client->clientPublicKey), false, clientKeyB64, &len))
    {
        goto done;
    }
    clientKeyB64[len] = 0;

    client->socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (client->socketFd < 0)
    {
        goto done;
    }
    timeout.tv_sec = 5;
    if (setsockopt(client->socketFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
    {
        goto done;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_COMMAND_HTTP_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(client->socketFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        goto done;
    }
    textLen = snprintf(body, sizeof(body), "{\"clientNonce\":\"%s\",\"clientPublicKey\":\"%s\"}", clientNonceB64, clientKeyB64);
    if (textLen <= 0 || static_cast<size_t>(textLen) >= sizeof(body) ||
        !commandTestPost(client->socketFd, "/ws/init", body, response, sizeof(response), &responseBody) ||
        !commandTestJsonString(responseBody, "token", tokenB64, sizeof(tokenB64)) ||
        !commandTestJsonString(responseBody, "serverNonce", serverNonceB64, sizeof(serverNonceB64)) ||
        !commandTestJsonString(responseBody, "serverPublicKey", serverKeyB64, sizeof(serverKeyB64)))
    {
        goto done;
    }
    len = sizeof(client->token);
    if (!fromB64(tokenB64, strlen(tokenB64), false, client->token, &len) || len != sizeof(client->token))
    {
        goto done;
    }
    len = sizeof(client->serverNonce);
    if (!fromB64(serverNonceB64, strlen(serverNonceB64), false, client->serverNonce, &len) || len != sizeof(client->serverNonce))
    {
        goto done;
    }
    len = sizeof(serverKey);
    if (!fromB64(serverKeyB64, strlen(serverKeyB64), false, serverKey, &len) || len != sizeof(serverKey))
    {
        goto done;
    }
    if (p256LoadPublicKey(&client->ecdhKey, serverKey) != ESP_OK || ecdhComputeSharedSecret(&client->ecdhKey, sharedSecret) != ESP_OK ||
        !commandTestLoginSalt(client, nullptr, 0, salt) ||
        hkdfSha256DeriveKey(sharedSecret, sizeof(sharedSecret), salt, sizeof(salt), reinterpret_cast<const uint8_t*>("mx-iot-auth-v1"),
                            strlen("mx-iot-auth-v1"), authKey, sizeof(authKey)) != ESP_OK || randomize(authNonce, sizeof(authNonce)) != ESP_OK)
    {
        goto done;
    }
    {
        static const uint8_t label[] = "ws-login-v1/user-auth";
        const uint8_t* parts[] = {label, client->clientPublicKey, serverKey, client->clientNonce, client->serverNonce, client->token,
                                  authNonce, reinterpret_cast<const uint8_t*>("root")};
        const size_t lengths[] = {sizeof(label) - 1, 65, 65, 16, 16, 12, 16, 4};

        if (!commandTestHash(hash, parts, lengths, sizeof(parts) / sizeof(parts[0])) || ecdsaSign(&testCtx->rootKey, hash, signature) != ESP_OK ||
            randomize(authIv, sizeof(authIv)) != ESP_OK)
        {
            goto done;
        }
    }
    len = sizeof(authNonceB64) - 1;
    if (!toB64(authNonce, sizeof(authNonce), false, authNonceB64, &len))
    {
        goto done;
    }
    authNonceB64[len] = 0;
    len = sizeof(signatureB64) - 1;
    if (!toB64(signature, sizeof(signature), false, signatureB64, &len))
    {
        goto done;
    }
    signatureB64[len] = 0;
    textLen = snprintf(body, sizeof(body), "{\"userName\":\"root\",\"authNonce\":\"%s\",\"signature\":\"%s\"}", authNonceB64,
                       signatureB64);
    if (textLen <= 0 || static_cast<size_t>(textLen) >= sizeof(body))
    {
        goto done;
    }
    {
        AesContext_t aes = {};

        aesInit(&aes);
        if (aesSetKey(&aes, authKey, sizeof(authKey)) != ESP_OK ||
            aesEncrypt(&aes, reinterpret_cast<const uint8_t*>(body), strlen(body), authIv, sizeof(authIv), nullptr, 0, encryptedAuth) != ESP_OK)
        {
            aesDone(&aes);
            goto done;
        }
        aesDone(&aes);
    }
    len = sizeof(authIvB64) - 1;
    if (!toB64(authIv, sizeof(authIv), false, authIvB64, &len))
    {
        goto done;
    }
    authIvB64[len] = 0;
    len = sizeof(encryptedB64) - 1;
    if (!toB64(encryptedAuth, strlen(body) + 16, false, encryptedB64, &len))
    {
        goto done;
    }
    encryptedB64[len] = 0;
    len = sizeof(tokenB64) - 1;
    if (!toB64(client->token, sizeof(client->token), false, tokenB64, &len))
    {
        goto done;
    }
    tokenB64[len] = 0;
    textLen = snprintf(body, sizeof(body), "{\"token\":\"%s\",\"authIv\":\"%s\",\"encryptedAuth\":\"%s\"}", tokenB64, authIvB64,
                       encryptedB64);
    if (textLen <= 0 || static_cast<size_t>(textLen) >= sizeof(body) ||
        !commandTestPost(client->socketFd, "/ws/auth", body, response, sizeof(response), &responseBody) ||
        !commandTestJsonString(responseBody, "wsNonce", wsNonceB64, sizeof(wsNonceB64)) ||
        !commandTestJsonString(responseBody, "wsTicket", ticketB64, sizeof(ticketB64)))
    {
        goto done;
    }
    len = sizeof(client->wsNonce);
    if (!fromB64(wsNonceB64, strlen(wsNonceB64), false, client->wsNonce, &len) || len != sizeof(client->wsNonce) ||
        !commandTestLoginSalt(client, nullptr, 0, salt) ||
        hkdfSha256DeriveKey(sharedSecret, sizeof(sharedSecret), salt, sizeof(salt),
                            reinterpret_cast<const uint8_t*>("mx-iot-session-master-v1"), strlen("mx-iot-session-master-v1"),
                            client->masterKey, sizeof(client->masterKey)) != ESP_OK || !commandTestLoginSalt(client, client->wsNonce, 16, salt) ||
        hkdfSha256DeriveKey(client->masterKey, sizeof(client->masterKey), salt, sizeof(salt), reinterpret_cast<const uint8_t*>("mx-iot-ws-v1"),
                            strlen("mx-iot-ws-v1"), derived, sizeof(derived)) != ESP_OK ||
        aesSetKey(&client->clientAes, derived, 32) != ESP_OK || aesSetKey(&client->serverAes, derived + 32, 32) != ESP_OK)
    {
        goto done;
    }
    memcpy(client->clientBaseIv, derived + 64, 12);
    memcpy(client->serverBaseIv, derived + 76, 12);
    textLen = snprintf(request, sizeof(request),
                       "GET /ws?wsTicket=%s HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                       ticketB64);
    if (textLen <= 0 || static_cast<size_t>(textLen) >= sizeof(request) || !commandTestSendAll(client->socketFd, request, textLen) ||
        !commandTestReadHttp(client->socketFd, response, sizeof(response), &responseBody))
    {
        goto done;
    }
    client->nextClientCounter = 1;
    client->nextServerCounter = 1;
    ok = true;

done:
    memset(authKey, 0, sizeof(authKey));
    memset(sharedSecret, 0, sizeof(sharedSecret));
    memset(derived, 0, sizeof(derived));
    memset(encryptedAuth, 0, sizeof(encryptedAuth));
    if (!ok)
    {
        commandTestClientClose(client);
    }
    return ok;
}

static void commandTestClientClose(CommandTestClient_t* client)
{
    if (client->socketFd >= 0)
    {
        close(client->socketFd);
    }
    aesDone(&client->clientAes);
    aesDone(&client->serverAes);
    p256KeyPairDone(&client->ecdhKey);
    memset(client, 0, sizeof(*client));
    client->socketFd = -1;
}

static bool commandTestCommand(CommandTestClient_t* client, uint16_t cmd, const uint8_t* request, size_t requestLen, uint8_t* reply,
                               size_t* replyLen)
{
    uint8_t packet[512];
    uint8_t iv[12];
    size_t packetLen = 12 + requestLen + 16;
    size_t receivedLen = sizeof(packet);
    uint64_t requestCounter = client->nextClientCounter;
    uint64_t serverCounter;

    if (packetLen > sizeof(packet))
    {
        ESP_LOGE("IotCommTest", "Command 0x%04X is too large for the test buffer.", cmd);
        return false;
    }
    packet[0] = 1;
    be16enc(packet + 1, cmd);
    packet[3] = 0;
    be64enc(packet + 4, requestCounter);
    commandTestIv(client->clientBaseIv, requestCounter, iv);
    if (aesEncrypt(&client->clientAes, request, requestLen, iv, sizeof(iv), packet, 12, packet + 12) != ESP_OK)
    {
        ESP_LOGE("IotCommTest", "Failed to encrypt command 0x%04X.", cmd);
        return false;
    }
    if (!commandTestSendWs(client->socketFd, packet, packetLen))
    {
        ESP_LOGE("IotCommTest", "Failed to send command 0x%04X.", cmd);
        return false;
    }
    if (!commandTestRecvWs(client->socketFd, packet, &receivedLen))
    {
        ESP_LOGE("IotCommTest", "Failed to receive reply for command 0x%04X.", cmd);
        return false;
    }
    if (receivedLen < 36 || packet[0] != 1 || be16dec(packet + 1) != cmd || packet[3] != 1 ||
        be64dec(packet + 12) != requestCounter)
    {
        ESP_LOGE("IotCommTest", "Invalid reply header for command 0x%04X (length %u).", cmd, static_cast<unsigned>(receivedLen));
        return false;
    }
    serverCounter = be64dec(packet + 4);
    if (serverCounter != client->nextServerCounter || receivedLen - 36 > *replyLen)
    {
        ESP_LOGE("IotCommTest", "Invalid reply counter or length for command 0x%04X.", cmd);
        return false;
    }
    commandTestIv(client->serverBaseIv, serverCounter, iv);
    if (aesDecrypt(&client->serverAes, packet + 20, receivedLen - 20, iv, sizeof(iv), packet, 20, reply) != ESP_OK)
    {
        ESP_LOGE("IotCommTest", "Failed to decrypt reply for command 0x%04X.", cmd);
        return false;
    }
    *replyLen = receivedLen - 36;
    client->nextClientCounter += 1;
    client->nextServerCounter += 1;
    return true;
}

static bool commandTestChangeRoot(CommandTestClient_t* client, CommandTestContext_t* testCtx)
{
    uint8_t publicKey[P256_PUBLIC_KEY_SIZE];
    uint8_t signature[P256_SIGNATURE_SIZE];
    uint8_t hash[SHA256_SIZE];
    uint8_t request[P256_SIGNATURE_SIZE + P256_PUBLIC_KEY_SIZE];
    uint8_t reply[8];
    size_t replyLen = sizeof(reply);
    static const uint8_t label[] = "ws-chgcreds-v1";
    const uint8_t* parts[] = {label, publicKey, client->wsNonce};
    const size_t lengths[] = {sizeof(label) - 1, sizeof(publicKey), sizeof(client->wsNonce)};

    if (p256SavePublicKey(&testCtx->rootKey, publicKey) != ESP_OK ||
        !commandTestHash(hash, parts, lengths, sizeof(parts) / sizeof(parts[0])) || ecdsaSign(&testCtx->rootKey, hash, signature) != ESP_OK)
    {
        return false;
    }
    memcpy(request, signature, sizeof(signature));
    memcpy(request + sizeof(signature), publicKey, sizeof(publicKey));
    return commandTestCommand(client, TEST_CMD_CHANGE_USER_CREDENTIALS, request, sizeof(request), reply, &replyLen) && replyLen == 4 &&
           be32dec(reply) == ESP_OK;
}

static bool commandTestCreateUser(CommandTestClient_t* client)
{
    P256KeyPair_t userKey = {};
    uint8_t publicKey[P256_PUBLIC_KEY_SIZE];
    uint8_t request[1 + sizeof("loopback-user") + P256_PUBLIC_KEY_SIZE];
    uint8_t reply[8];
    size_t replyLen = sizeof(reply);
    bool ok;

    p256KeyPairInit(&userKey);
    ok = ecdsaGeneratePair(&userKey) == ESP_OK && p256SavePublicKey(&userKey, publicKey) == ESP_OK;
    if (ok)
    {
        request[0] = 0;
        memcpy(request + 1, "loopback-user", sizeof("loopback-user"));
        memcpy(request + 1 + sizeof("loopback-user"), publicKey, sizeof(publicKey));
        ok = commandTestCommand(client, TEST_CMD_CREATE_USER, request, sizeof(request), reply, &replyLen) && replyLen == 4 &&
             be32dec(reply) == ESP_OK;
    }
    p256KeyPairDone(&userKey);
    return ok;
}

static bool commandTestOpenUdp(CommandTestClient_t* client, uint16_t* port, uint32_t* id, uint8_t key[32], uint8_t baseIv[12])
{
    uint8_t clientNonce[16];
    uint8_t serverNonce[16];
    uint8_t reply[32];
    uint8_t salt[SHA256_SIZE];
    uint8_t derived[88];
    uint8_t idBytes[4];
    size_t replyLen = sizeof(reply);
    static const uint8_t label[] = "udp-open-v1";
    const uint8_t* parts[] = {label, clientNonce, serverNonce, idBytes};
    const size_t lengths[] = {sizeof(label) - 1, sizeof(clientNonce), sizeof(serverNonce), sizeof(idBytes)};

    if (randomize(clientNonce, sizeof(clientNonce)) != ESP_OK ||
        !commandTestCommand(client, TEST_CMD_UDP_OPEN, clientNonce, sizeof(clientNonce), reply, &replyLen) || replyLen != 26 ||
        be32dec(reply) != ESP_OK)
    {
        return false;
    }
    *port = be16dec(reply + 4);
    *id = be32dec(reply + 6);
    if (*port != TEST_COMMAND_UDP_PORT || *id == 0)
    {
        return false;
    }
    memcpy(serverNonce, reply + 10, sizeof(serverNonce));
    be32enc(idBytes, *id);
    if (!commandTestHash(salt, parts, lengths, sizeof(parts) / sizeof(parts[0])) ||
        hkdfSha256DeriveKey(client->masterKey, sizeof(client->masterKey), salt, sizeof(salt), reinterpret_cast<const uint8_t*>("mx-iot-udp-v1"),
                            strlen("mx-iot-udp-v1"), derived, sizeof(derived)) != ESP_OK)
    {
        return false;
    }
    memcpy(key, derived, 32);
    memcpy(baseIv, derived + 64, 12);
    memset(derived, 0, sizeof(derived));
    return true;
}

static bool commandTestSendUdp(int socketFd, uint16_t port, uint32_t id, const uint8_t key[32], const uint8_t baseIv[12], uint16_t cmd,
                               uint64_t counter, const uint8_t* payload, size_t payloadLen)
{
    uint8_t packet[16 + 16 + 16];
    uint8_t iv[12];
    AesContext_t aes = {};
    struct sockaddr_in addr = {};
    bool ok;

    if (socketFd < 0 || (!payload && payloadLen != 0) || payloadLen > sizeof(packet) - 16 - 16)
    {
        return false;
    }

    be32enc(packet, id);
    packet[4] = 1;
    be16enc(packet + 5, cmd);
    packet[7] = 0;
    be64enc(packet + 8, counter);
    if (payloadLen > 0)
    {
        memcpy(packet + 16, payload, payloadLen);
    }
    commandTestIv(baseIv, counter, iv);
    aesInit(&aes);
    ok = aesSetKey(&aes, key, 32) == ESP_OK &&
          aesEncrypt(&aes, packet + 16, payloadLen, iv, sizeof(iv), packet, 16, packet + 16) == ESP_OK;
    aesDone(&aes);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (ok)
    {
        size_t packetLen = 16 + payloadLen + 16;

        ok = sendto(socketFd, packet, packetLen, 0, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == static_cast<int>(packetLen);
    }
    return ok;
}

static void commandTestClientTask(void* arg)
{
    CommandTestContext_t* testCtx = static_cast<CommandTestContext_t*>(arg);
    CommandTestClient_t client = {};
    uint16_t port;
    uint32_t id;
    uint8_t udpKey[32];
    uint8_t udpBaseIv[12];
    uint8_t udpOpenNonce[16];
    uint8_t udpReply[1];
    int udpSocketFd = -1;
    const char* failedAt = "open";

    testCtx->clientErr = ESP_FAIL;
    if (commandTestClientOpen(&client, testCtx))
    {
        failedAt = "change root credentials";
        if (commandTestChangeRoot(&client, testCtx))
        {
            failedAt = "create user";
            if (commandTestCreateUser(&client))
            {
                failedAt = "open UDP";
                if (commandTestOpenUdp(&client, &port, &id, udpKey, udpBaseIv))
                {
                    // The negotiation reply is queued before the server commits the UDP snapshot.
                    vTaskDelay(pdMS_TO_TICKS(20));
                    failedAt = "send UDP built-in command";
                    udpSocketFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
                    struct timeval timeout = {};

                    timeout.tv_usec = 250000;

                    if (udpSocketFd >= 0 && setsockopt(udpSocketFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
                        randomize(udpOpenNonce, sizeof(udpOpenNonce)) == ESP_OK &&
                        commandTestSendUdp(udpSocketFd, port, id, udpKey, udpBaseIv, TEST_CMD_UDP_OPEN, 1, udpOpenNonce,
                                           sizeof(udpOpenNonce)))
                    {
                        failedAt = "reject custom command using invalidated UDP state";
                        if (commandTestSendUdp(udpSocketFd, port, id, udpKey, udpBaseIv, TEST_UDP_COMMAND, 2,
                                               reinterpret_cast<const uint8_t*>("old"), 3) &&
                            xSemaphoreTake(testCtx->udpReceived, pdMS_TO_TICKS(500)) != pdTRUE)
                        {
                            failedAt = "reopen UDP";
                            if (commandTestOpenUdp(&client, &port, &id, udpKey, udpBaseIv))
                            {
                                // The negotiation reply is queued before the server commits the UDP snapshot.
                                vTaskDelay(pdMS_TO_TICKS(20));
                                failedAt = "send or receive UDP custom command";
                                if (commandTestSendUdp(udpSocketFd, port, id, udpKey, udpBaseIv, TEST_UDP_COMMAND, 1,
                                                       reinterpret_cast<const uint8_t*>("udp"), 3) &&
                                    xSemaphoreTake(testCtx->udpReceived, pdMS_TO_TICKS(5000)) == pdTRUE &&
                                    recv(udpSocketFd, udpReply, sizeof(udpReply), 0) < 0)
                                {
                                    testCtx->clientErr = ESP_OK;
                                    xSemaphoreGive(testCtx->sessionReady);
                                    xSemaphoreTake(testCtx->clientRelease, pdMS_TO_TICKS(5000));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (testCtx->clientErr != ESP_OK)
    {
        ESP_LOGE("IotCommTest", "Loopback command client failed at: %s", failedAt);
    }
    memset(udpKey, 0, sizeof(udpKey));
    memset(udpOpenNonce, 0, sizeof(udpOpenNonce));
    if (udpSocketFd >= 0)
    {
        close(udpSocketFd);
    }
    commandTestClientClose(&client);
    xSemaphoreGive(testCtx->done);
    vTaskDelete(nullptr);
}
