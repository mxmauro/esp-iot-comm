#include <unity.h>
#include <iot_comm/iot_comm.h>
#include <iot_comm/crypto/p256.h>
#include <iot_comm/crypto/utils.h>
#include <esp_event.h>
#include <esp_netif.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <convert.h>
#include <lwip/inet.h>
#include <lwip/sockets.h>
#include <string.h>

// -----------------------------------------------------------------------------

typedef struct TestStorageItem_s {
    uint8_t* data;
    size_t   len;
} TestStorageItem_t;

typedef struct LoopbackTestContext_s {
    P256KeyPair_t    rootKey;
    TestStorageItem_t storage[3];
    SemaphoreHandle_t done;
    esp_err_t         clientErr;
} LoopbackTestContext_t;

// -----------------------------------------------------------------------------

static esp_err_t loadStorage(IotCommStorageItemType_t type, void* dest, size_t destLen, void* ctx);
static esp_err_t saveStorage(IotCommStorageItemType_t type, const void* data, size_t dataLen, void* ctx);
static esp_err_t getRootPublicKey(uint8_t publicKey[P256_PUBLIC_KEY_SIZE], void* ctx);
static void eventHandler(IotCommEvent_t* event);
static bool sendAll(int socketFd, const char* data, size_t len);
static void loopbackClientTask(void* arg);

// -----------------------------------------------------------------------------

TEST_CASE("IoT-Comm serves WebSocket initialization over loopback", "[iot_comm][integration]")
{
    LoopbackTestContext_t testCtx = {};
    IotCommConfig_t config = iotCommDefaultConfig();
    IotCommServerConfig_t serverConfig = iotCommDefaultServerConfig();
    uint8_t hash[P256_HASH_SIZE] = {};
    uint8_t signature[P256_SIGNATURE_SIZE] = {};
    esp_err_t err;

    err = esp_event_loop_create_default();
    TEST_ASSERT_TRUE(err == ESP_OK || err == ESP_ERR_INVALID_STATE);
    err = esp_netif_init();
    TEST_ASSERT_TRUE(err == ESP_OK || err == ESP_ERR_INVALID_STATE);
    p256KeyPairInit(&testCtx.rootKey);
    TEST_ASSERT_EQUAL(ESP_OK, ecdsaGeneratePair(&testCtx.rootKey));
    TEST_ASSERT_EQUAL(ESP_OK, ecdsaSign(&testCtx.rootKey, hash, signature));
    vTaskDelay(1);
    config.handler = eventHandler;
    config.handlerCtx = &testCtx;
    config.rootKey.cb = getRootPublicKey;
    config.rootKey.ctx = &testCtx;
    config.storage.load = loadStorage;
    config.storage.save = saveStorage;
    config.storage.ctx = &testCtx;
    TEST_ASSERT_EQUAL(ESP_OK, iotCommInit(&config));
    TEST_ASSERT_EQUAL(ESP_OK, iotCommVerifyRootUserSignature(hash, signature));
    serverConfig.listenPort = 18080;
    TEST_ASSERT_EQUAL(ESP_OK, iotCommStartServer(&serverConfig));
    TEST_ASSERT_EQUAL(ESP_OK, iotCommInit(nullptr));
    TEST_ASSERT_TRUE(iotCommIsServerRunning());
    testCtx.done = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(testCtx.done);
    TEST_ASSERT_EQUAL(pdPASS, xTaskCreate(loopbackClientTask, "iotcomm-client", 8192, &testCtx, 5, nullptr));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(testCtx.done, pdMS_TO_TICKS(10000)));
    TEST_ASSERT_EQUAL(ESP_OK, testCtx.clientErr);
    iotCommStopServer();
    iotCommDeinit();
    vSemaphoreDelete(testCtx.done);
    p256KeyPairDone(&testCtx.rootKey);
    for (TestStorageItem_t& item : testCtx.storage)
    {
        if (item.data)
        {
            memset(item.data, 0, item.len);
            free(item.data);
        }
    }
}

// -----------------------------------------------------------------------------

static esp_err_t loadStorage(IotCommStorageItemType_t type, void* dest, size_t destLen, void* ctx)
{
    LoopbackTestContext_t* testCtx = static_cast<LoopbackTestContext_t*>(ctx);
    TestStorageItem_t* item = &testCtx->storage[type];

    if (!item->data)
    {
        return ESP_ERR_NOT_FOUND;
    }
    if (item->len != destLen)
    {
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(dest, item->data, destLen);
    return ESP_OK;
}

static esp_err_t saveStorage(IotCommStorageItemType_t type, const void* data, size_t dataLen, void* ctx)
{
    LoopbackTestContext_t* testCtx = static_cast<LoopbackTestContext_t*>(ctx);
    TestStorageItem_t* item = &testCtx->storage[type];
    uint8_t* copy = static_cast<uint8_t*>(malloc(dataLen));

    if (!copy)
    {
        return ESP_ERR_NO_MEM;
    }
    memcpy(copy, data, dataLen);
    if (item->data)
    {
        memset(item->data, 0, item->len);
        free(item->data);
    }
    item->data = copy;
    item->len = dataLen;
    return ESP_OK;
}

static esp_err_t getRootPublicKey(uint8_t publicKey[P256_PUBLIC_KEY_SIZE], void* ctx)
{
    return p256SavePublicKey(&static_cast<LoopbackTestContext_t*>(ctx)->rootKey, publicKey);
}

static void eventHandler(IotCommEvent_t* event)
{
    (void)event;
}

static bool sendAll(int socketFd, const char* data, size_t len)
{
    while (len > 0)
    {
        int sent = send(socketFd, data, len, 0);

        if (sent <= 0)
        {
            return false;
        }
        data += sent;
        len -= static_cast<size_t>(sent);
    }
    return true;
}

static void loopbackClientTask(void* arg)
{
    LoopbackTestContext_t* testCtx = static_cast<LoopbackTestContext_t*>(arg);
    P256KeyPair_t ecdhKey = {};
    uint8_t nonce[16];
    uint8_t publicKey[P256_PUBLIC_KEY_SIZE];
    char nonceB64[32];
    char publicKeyB64[96];
    char body[192];
    char request[320];
    char response[768];
    struct sockaddr_in addr = {};
    int socketFd = -1;
    size_t nonceB64Len = sizeof(nonceB64) - 1;
    size_t publicKeyB64Len = sizeof(publicKeyB64) - 1;
    int bodyLen = 0;
    int requestLen = 0;
    size_t responseUsed = 0;

    testCtx->clientErr = ESP_FAIL;
    p256KeyPairInit(&ecdhKey);
    if (randomize(nonce, sizeof(nonce)) != ESP_OK || ecdhGeneratePair(&ecdhKey) != ESP_OK ||
        p256SavePublicKey(&ecdhKey, publicKey) != ESP_OK || !toB64(nonce, sizeof(nonce), false, nonceB64, &nonceB64Len) ||
        !toB64(publicKey, sizeof(publicKey), false, publicKeyB64, &publicKeyB64Len))
    {
        goto done;
    }
    nonceB64[nonceB64Len] = 0;
    publicKeyB64[publicKeyB64Len] = 0;
    socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (socketFd < 0)
    {
        goto done;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(18080);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(socketFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        goto done;
    }
    bodyLen = snprintf(body, sizeof(body), "{\"clientNonce\":\"%s\",\"clientPublicKey\":\"%s\"}", nonceB64, publicKeyB64);
    if (bodyLen <= 0 || static_cast<size_t>(bodyLen) >= sizeof(body))
    {
        goto done;
    }
    requestLen = snprintf(request, sizeof(request),
                          "POST /ws/init HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: %u\r\n\r\n%s",
                          static_cast<unsigned>(bodyLen), body);
    if (requestLen <= 0 || static_cast<size_t>(requestLen) >= sizeof(request) || !sendAll(socketFd, request, requestLen))
    {
        goto done;
    }
    while (responseUsed < sizeof(response) - 1)
    {
        char* bodyStart;
        char* contentLength;
        int responseLen = recv(socketFd, response + responseUsed, sizeof(response) - 1 - responseUsed, 0);

        if (responseLen <= 0)
        {
            break;
        }
        responseUsed += static_cast<size_t>(responseLen);
        response[responseUsed] = 0;
        bodyStart = strstr(response, "\r\n\r\n");
        contentLength = strstr(response, "Content-Length: ");
        if (bodyStart && contentLength)
        {
            size_t expectedBodyLen = strtoul(contentLength + strlen("Content-Length: "), nullptr, 10);
            size_t headerLen = static_cast<size_t>(bodyStart + 4 - response);

            if (responseUsed >= headerLen + expectedBodyLen)
            {
                break;
            }
        }
    }
    if (strstr(response, "HTTP/1.1 200") && strstr(response, "serverPublicKey") && strstr(response, "deviceSignature"))
    {
        testCtx->clientErr = ESP_OK;
    }

done:
    if (socketFd >= 0)
    {
        close(socketFd);
    }
    memset(nonce, 0, sizeof(nonce));
    memset(publicKey, 0, sizeof(publicKey));
    p256KeyPairDone(&ecdhKey);
    xSemaphoreGive(testCtx->done);
    vTaskDelete(nullptr);
}
