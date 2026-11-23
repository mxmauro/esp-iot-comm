#include <unity.h>
#include <iot_comm/iot_comm.h>
#include <iot_comm/crypto/ecc.h>
#include <iot_comm/crypto/utils.h>
#include <esp_event.h>
#include <esp_netif.h>
#include <freertos/event_groups.h>
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
    bool              extraUriCalled;
    size_t            extraUriCalls;
    EventGroupHandle_t multiCoreSync;
    esp_err_t          multiCoreClientErr[2];
    BaseType_t         multiCoreClientCore[2];
    size_t             multiCoreActiveRequests;
    size_t             multiCoreMaxActiveRequests;
} LoopbackTestContext_t;

typedef struct MultiCoreRequestTaskArgs_s {
    LoopbackTestContext_t* testCtx;
    EventBits_t            readyBit;
    EventBits_t            doneBit;
    size_t                 index;
} MultiCoreRequestTaskArgs_t;

// -----------------------------------------------------------------------------

static constexpr EventBits_t kMultiCoreStartBit = BIT0;
static constexpr EventBits_t kMultiCoreClient0ReadyBit = BIT1;
static constexpr EventBits_t kMultiCoreClient1ReadyBit = BIT2;
static constexpr EventBits_t kMultiCoreClient0DoneBit = BIT3;
static constexpr EventBits_t kMultiCoreClient1DoneBit = BIT4;

// -----------------------------------------------------------------------------

static esp_err_t loadStorage(IotCommStorageItemType_t type, void* dest, size_t destLen, void* ctx);
static esp_err_t saveStorage(IotCommStorageItemType_t type, const void* data, size_t dataLen, void* ctx);
static esp_err_t getRootPublicKey(uint8_t publicKey[P256_PUBLIC_KEY_SIZE], void* ctx);
static void eventHandler(IotCommEvent_t* event);
static esp_err_t extraUriHandler(httpd_req_t* req);
static esp_err_t extraUriErrorHandler(httpd_req_t* req);
static void freeTestStorage(LoopbackTestContext_t* testCtx);
static bool sendAll(int socketFd, const char* data, size_t len);
static bool receiveHttpResponse(int socketFd, char* response, size_t responseSize);
static void loopbackClientTask(void* arg);
static void wildcardCorsClientTask(void* arg);
static void multiCoreRequestTask(void* arg);

// -----------------------------------------------------------------------------

TEST_CASE("IoT-Comm serves WebSocket initialization over loopback", "[iot_comm][integration]")
{
    LoopbackTestContext_t testCtx = {};
    IotCommConfig_t config = iotCommDefaultConfig();
    IotCommServerConfig_t serverConfig = iotCommDefaultServerConfig();
    IotCommCORSConfig_t corsConfig = iotCommDefaultCORSConfig();
    IotCommHttpEndpoint_t extraUriHandlers[5] = {};
    uint8_t hash[P256_HASH_SIZE] = {};
    uint8_t signature[P256_SIGNATURE_SIZE] = {};
    uint8_t identityPublicKey[P256_PUBLIC_KEY_SIZE] = {};
    uint8_t identitySignature[P256_SIGNATURE_SIZE] = {};
    P256KeyPair_t identityVerifier = {};
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
    config.rateLimit.maxRequestsPerWindow = 4;
    TEST_ASSERT_EQUAL(ESP_OK, iotCommInit(&config));
    TEST_ASSERT_EQUAL(ESP_OK, iotCommVerifyRootUserSignature(hash, signature));
    p256KeyPairInit(&identityVerifier);
    TEST_ASSERT_EQUAL(ESP_OK, iotCommGetDeviceIdentityPublicKey(identityPublicKey));
    TEST_ASSERT_EQUAL(ESP_OK, iotCommSignDeviceIdentityHash(hash, identitySignature));
    TEST_ASSERT_EQUAL(ESP_OK, p256LoadPublicKey(&identityVerifier, identityPublicKey));
    TEST_ASSERT_EQUAL(ESP_OK, ecdsaVerify(&identityVerifier, hash, identitySignature));
    p256KeyPairDone(&identityVerifier);
    serverConfig.listenPort = 18080;
    for (size_t i = 0; i < sizeof(extraUriHandlers) / sizeof(extraUriHandlers[0]); i++)
    {
        extraUriHandlers[i].uri = (i == 4) ? "/extra/error" : (i == 3) ? "/extra/multicore" : (i == 2) ? "/extra/three"
                                                                                                        : (i == 1) ? "/extra/two"
                                                                                                                   : "/extra/one";
        extraUriHandlers[i].method = HTTP_GET;
        extraUriHandlers[i].handler = (i == 4) ? extraUriErrorHandler : extraUriHandler;
        extraUriHandlers[i].ctx = &testCtx;
        extraUriHandlers[i].rateLimit = i == 1;
    }
    serverConfig.cors = &corsConfig;
    serverConfig.extraUriHandlers = extraUriHandlers;
    serverConfig.extraUriHandlersCount = sizeof(extraUriHandlers) / sizeof(extraUriHandlers[0]);
    TEST_ASSERT_EQUAL(ESP_OK, iotCommStartServer(&serverConfig));
    extraUriHandlers[2].ctx = nullptr;
    TEST_ASSERT_EQUAL(ESP_OK, iotCommInit(nullptr));
    TEST_ASSERT_TRUE(iotCommIsServerRunning());
    testCtx.done = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(testCtx.done);
    TEST_ASSERT_EQUAL(pdPASS, xTaskCreate(loopbackClientTask, "iotcomm-client", 8192, &testCtx, 5, nullptr));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(testCtx.done, pdMS_TO_TICKS(10000)));
    TEST_ASSERT_EQUAL(ESP_OK, testCtx.clientErr);
    TEST_ASSERT_TRUE(testCtx.extraUriCalled);
    TEST_ASSERT_EQUAL_UINT32(5, testCtx.extraUriCalls);
    iotCommStopServer();
    IotCommHttpEndpoint_t wildcardEndpoint = {
        .uri = "/extra/wildcard",
        .method = HTTP_GET,
        .handler = extraUriHandler,
        .ctx = &testCtx,
        .rateLimit = false,
    };
    IotCommCORSConfig_t wildcardCORSConfig = iotCommDefaultCORSConfig();

    wildcardCORSConfig.useWildcardOrigin = true;
    serverConfig.listenPort = 18082;
    serverConfig.cors = &wildcardCORSConfig;
    serverConfig.extraUriHandlers = &wildcardEndpoint;
    serverConfig.extraUriHandlersCount = 1;
    TEST_ASSERT_EQUAL(ESP_OK, iotCommStartServer(&serverConfig));
    TEST_ASSERT_EQUAL(pdPASS, xTaskCreate(wildcardCorsClientTask, "iotcomm-cors", 4096, &testCtx, 5, nullptr));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(testCtx.done, pdMS_TO_TICKS(10000)));
    TEST_ASSERT_EQUAL(ESP_OK, testCtx.clientErr);
    iotCommStopServer();
    serverConfig.listenPort = 18080;
    serverConfig.cors = &corsConfig;
    serverConfig.extraUriHandlers = nullptr;
    serverConfig.extraUriHandlersCount = 1;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, iotCommStartServer(&serverConfig));
    IotCommHttpEndpoint_t invalidEndpoint = {};

    serverConfig.extraUriHandlers = &invalidEndpoint;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, iotCommStartServer(&serverConfig));
    serverConfig.extraUriHandlers = extraUriHandlers;
    serverConfig.extraUriHandlersCount = 1;
    corsConfig.allowedMethods = nullptr;
    TEST_ASSERT_EQUAL(ESP_OK, iotCommStartServer(&serverConfig));
    iotCommStopServer();
    corsConfig.allowedMethods = "";
    TEST_ASSERT_EQUAL(ESP_OK, iotCommStartServer(&serverConfig));
    iotCommStopServer();
    corsConfig = iotCommDefaultCORSConfig();
    corsConfig.allowedHeaders = nullptr;
    TEST_ASSERT_EQUAL(ESP_OK, iotCommStartServer(&serverConfig));
    iotCommStopServer();
    corsConfig.allowedHeaders = "";
    TEST_ASSERT_EQUAL(ESP_OK, iotCommStartServer(&serverConfig));
    iotCommStopServer();
    corsConfig = iotCommDefaultCORSConfig();
    invalidEndpoint.uri = "/extra/options";
    invalidEndpoint.method = HTTP_OPTIONS;
    invalidEndpoint.handler = extraUriHandler;
    serverConfig.extraUriHandlers = &invalidEndpoint;
    serverConfig.extraUriHandlersCount = 1;
    serverConfig.cors = &corsConfig;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, iotCommStartServer(&serverConfig));
    invalidEndpoint.uri = "/__iot_comm_cors_fallback__";
    invalidEndpoint.method = HTTP_GET;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, iotCommStartServer(&serverConfig));
    TEST_ASSERT_FALSE(iotCommIsServerRunning());
    iotCommDeinit();
    vSemaphoreDelete(testCtx.done);
    p256KeyPairDone(&testCtx.rootKey);
    freeTestStorage(&testCtx);
    memset(identitySignature, 0, sizeof(identitySignature));
}

TEST_CASE("IoT-Comm serializes loopback endpoint requests from two cores", "[iot_comm][integration][multicore]")
{
    if (portNUM_PROCESSORS < 2)
    {
        TEST_IGNORE_MESSAGE("requires a multicore target");
    }

    LoopbackTestContext_t testCtx = {};
    MultiCoreRequestTaskArgs_t taskArgs[2] = {
        {.testCtx = &testCtx, .readyBit = kMultiCoreClient0ReadyBit, .doneBit = kMultiCoreClient0DoneBit, .index = 0},
        {.testCtx = &testCtx, .readyBit = kMultiCoreClient1ReadyBit, .doneBit = kMultiCoreClient1DoneBit, .index = 1},
    };
    IotCommConfig_t config = iotCommDefaultConfig();
    IotCommServerConfig_t serverConfig = iotCommDefaultServerConfig();
    IotCommHttpEndpoint_t endpoint = {
        .uri = "/extra/multicore",
        .method = HTTP_GET,
        .handler = extraUriHandler,
        .ctx = &testCtx,
        .rateLimit = false,
    };
    EventBits_t bits;
    esp_err_t err;
    BaseType_t currentCore;

    err = esp_event_loop_create_default();
    TEST_ASSERT_TRUE(err == ESP_OK || err == ESP_ERR_INVALID_STATE);
    err = esp_netif_init();
    TEST_ASSERT_TRUE(err == ESP_OK || err == ESP_ERR_INVALID_STATE);
    p256KeyPairInit(&testCtx.rootKey);
    TEST_ASSERT_EQUAL(ESP_OK, ecdsaGeneratePair(&testCtx.rootKey));
    config.handler = eventHandler;
    config.handlerCtx = &testCtx;
    config.rootKey.cb = getRootPublicKey;
    config.rootKey.ctx = &testCtx;
    config.storage.load = loadStorage;
    config.storage.save = saveStorage;
    config.storage.ctx = &testCtx;
    TEST_ASSERT_EQUAL(ESP_OK, iotCommInit(&config));
    serverConfig.listenPort = 18081;
    serverConfig.extraUriHandlers = &endpoint;
    serverConfig.extraUriHandlersCount = 1;
    TEST_ASSERT_EQUAL(ESP_OK, iotCommStartServer(&serverConfig));

    testCtx.multiCoreSync = xEventGroupCreate();
    TEST_ASSERT_NOT_NULL(testCtx.multiCoreSync);
    currentCore = xPortGetCoreID();
    TEST_ASSERT_EQUAL(pdPASS, xTaskCreatePinnedToCore(multiCoreRequestTask, "iotcomm-mc-0", 4096, &taskArgs[0], 5, nullptr, currentCore));
    TEST_ASSERT_EQUAL(pdPASS, xTaskCreatePinnedToCore(multiCoreRequestTask, "iotcomm-mc-1", 4096, &taskArgs[1], 5, nullptr,
                                                      (currentCore + 1) % portNUM_PROCESSORS));
    bits = xEventGroupWaitBits(testCtx.multiCoreSync, kMultiCoreClient0ReadyBit | kMultiCoreClient1ReadyBit, pdFALSE, pdTRUE,
                               pdMS_TO_TICKS(10000));
    TEST_ASSERT_EQUAL(kMultiCoreClient0ReadyBit | kMultiCoreClient1ReadyBit,
                      bits & (kMultiCoreClient0ReadyBit | kMultiCoreClient1ReadyBit));
    TEST_ASSERT_EQUAL(currentCore, testCtx.multiCoreClientCore[0]);
    TEST_ASSERT_EQUAL((currentCore + 1) % portNUM_PROCESSORS, testCtx.multiCoreClientCore[1]);
    xEventGroupSetBits(testCtx.multiCoreSync, kMultiCoreStartBit);
    bits = xEventGroupWaitBits(testCtx.multiCoreSync, kMultiCoreClient0DoneBit | kMultiCoreClient1DoneBit, pdFALSE, pdTRUE,
                               pdMS_TO_TICKS(10000));
    TEST_ASSERT_EQUAL(kMultiCoreClient0DoneBit | kMultiCoreClient1DoneBit, bits & (kMultiCoreClient0DoneBit | kMultiCoreClient1DoneBit));
    TEST_ASSERT_EQUAL(ESP_OK, testCtx.multiCoreClientErr[0]);
    TEST_ASSERT_EQUAL(ESP_OK, testCtx.multiCoreClientErr[1]);
    TEST_ASSERT_EQUAL_UINT32(1, testCtx.multiCoreMaxActiveRequests);

    iotCommStopServer();
    iotCommDeinit();
    vEventGroupDelete(testCtx.multiCoreSync);
    p256KeyPairDone(&testCtx.rootKey);
    freeTestStorage(&testCtx);
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

static esp_err_t extraUriHandler(httpd_req_t* req)
{
    LoopbackTestContext_t* testCtx = static_cast<LoopbackTestContext_t*>(req->user_ctx);

    testCtx->extraUriCalled = true;
    testCtx->extraUriCalls += 1;
    if (strcmp(req->uri, "/extra/multicore") == 0)
    {
        // Two client tasks issue this request from different cores. The ESP-IDF
        // HTTP server must still invoke handlers serially in its one server task.
        testCtx->multiCoreActiveRequests += 1;
        if (testCtx->multiCoreActiveRequests > testCtx->multiCoreMaxActiveRequests)
        {
            testCtx->multiCoreMaxActiveRequests = testCtx->multiCoreActiveRequests;
        }
        vTaskDelay(1);
        testCtx->multiCoreActiveRequests -= 1;
    }
    return httpd_resp_sendstr(req, "extra");
}

static esp_err_t extraUriErrorHandler(httpd_req_t* req)
{
    return httpd_req_handle_err(req, HTTPD_400_BAD_REQUEST);
}

static void freeTestStorage(LoopbackTestContext_t* testCtx)
{
    for (TestStorageItem_t& item : testCtx->storage)
    {
        if (item.data)
        {
            memset(item.data, 0, item.len);
            free(item.data);
        }
    }
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

static bool receiveHttpResponse(int socketFd, char* response, size_t responseSize)
{
    size_t responseUsed = 0;

    while (responseUsed < responseSize - 1)
    {
        char* bodyStart;
        char* contentLength;
        int responseLen = recv(socketFd, response + responseUsed, responseSize - 1 - responseUsed, 0);

        if (responseLen <= 0)
        {
            return false;
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
                return true;
            }
        }
    }
    return false;
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
    char request[512];
    char response[1024];
    struct sockaddr_in addr = {};
    int socketFd = -1;
    size_t nonceB64Len = sizeof(nonceB64) - 1;
    size_t publicKeyB64Len = sizeof(publicKeyB64) - 1;
    int bodyLen = 0;
    int requestLen = 0;

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
    requestLen = snprintf(request, sizeof(request),
                          "GET /extra/three HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://example.test\r\n\r\n");
    if (requestLen <= 0 || static_cast<size_t>(requestLen) >= sizeof(request) || !sendAll(socketFd, request, requestLen) ||
        !receiveHttpResponse(socketFd, response, sizeof(response)) || !strstr(response, "HTTP/1.1 200") || !strstr(response, "extra") ||
        !strstr(response, "Access-Control-Allow-Origin: https://example.test") ||
        !strstr(response, "Access-Control-Allow-Credentials: true") ||
        !strstr(response, "Access-Control-Allow-Methods: GET,POST,OPTIONS") ||
        !strstr(response, "Access-Control-Allow-Headers: Content-Type, Authorization"))
    {
        goto done;
    }
    requestLen = snprintf(request, sizeof(request),
                          "OPTIONS /extra/three HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://example.test\r\n"
                          "Access-Control-Request-Method: GET\r\n\r\n");
    if (requestLen <= 0 || static_cast<size_t>(requestLen) >= sizeof(request) || !sendAll(socketFd, request, requestLen) ||
        !receiveHttpResponse(socketFd, response, sizeof(response)) || !strstr(response, "HTTP/1.1 204") ||
        !strstr(response, "Access-Control-Allow-Origin: https://example.test") || !strstr(response, "Content-Length: 0"))
    {
        goto done;
    }
    requestLen = snprintf(request, sizeof(request),
                          "OPTIONS /missing HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://example.test\r\n"
                          "Access-Control-Request-Method: GET\r\n\r\n");
    if (requestLen <= 0 || static_cast<size_t>(requestLen) >= sizeof(request) || !sendAll(socketFd, request, requestLen) ||
        !receiveHttpResponse(socketFd, response, sizeof(response)) || !strstr(response, "HTTP/1.1 204") ||
        !strstr(response, "Access-Control-Allow-Origin: https://example.test") || !strstr(response, "Content-Length: 0"))
    {
        goto done;
    }
    requestLen = snprintf(request, sizeof(request), "GET /extra/one HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    if (requestLen <= 0 || static_cast<size_t>(requestLen) >= sizeof(request) || !sendAll(socketFd, request, requestLen) ||
        !receiveHttpResponse(socketFd, response, sizeof(response)) || !strstr(response, "HTTP/1.1 200") || !strstr(response, "extra") ||
        !strstr(response, "Access-Control-Allow-Origin: *"))
    {
        goto done;
    }
    bodyLen = snprintf(body, sizeof(body), "{\"clientNonce\":\"%s\",\"clientPublicKey\":\"%s\"}", nonceB64, publicKeyB64);
    if (bodyLen <= 0 || static_cast<size_t>(bodyLen) >= sizeof(body))
    {
        goto done;
    }
    requestLen = snprintf(request, sizeof(request),
                          "POST /ws/init HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://example.test\r\nContent-Type: application/json\r\n"
                          "Content-Length: %u\r\n\r\n%s",
                          static_cast<unsigned>(bodyLen), body);
    if (requestLen <= 0 || static_cast<size_t>(requestLen) >= sizeof(request) || !sendAll(socketFd, request, requestLen))
    {
        goto done;
    }
    if (receiveHttpResponse(socketFd, response, sizeof(response)) && strstr(response, "HTTP/1.1 200") &&
        strstr(response, "serverPublicKey") && strstr(response, "deviceSignature") &&
        strstr(response, "Access-Control-Allow-Origin: https://example.test"))
    {
        for (size_t i = 0; i < 3; i++)
        {
            requestLen = snprintf(request, sizeof(request), "GET /extra/two HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            if (requestLen <= 0 || static_cast<size_t>(requestLen) >= sizeof(request) || !sendAll(socketFd, request, requestLen) ||
                !receiveHttpResponse(socketFd, response, sizeof(response)) || !strstr(response, "HTTP/1.1 200") || !strstr(response, "extra"))
            {
                goto done;
            }
        }
        requestLen = snprintf(request, sizeof(request), "GET /extra/two HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        if (requestLen > 0 && static_cast<size_t>(requestLen) < sizeof(request) && sendAll(socketFd, request, requestLen) &&
            receiveHttpResponse(socketFd, response, sizeof(response)) && strstr(response, "HTTP/1.1 429"))
        {
            requestLen = snprintf(request, sizeof(request),
                                  "POST http://127.0.0.1:18080/extra/three?value=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                                  "Origin: https://example.test\r\n\r\n");
            if (requestLen > 0 && static_cast<size_t>(requestLen) < sizeof(request) && sendAll(socketFd, request, requestLen) &&
                receiveHttpResponse(socketFd, response, sizeof(response)) && strstr(response, "HTTP/1.1 405") &&
                strstr(response, "Access-Control-Allow-Origin: https://example.test"))
            {
                close(socketFd);
                socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
                if (socketFd >= 0 && connect(socketFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0)
                {
                    requestLen = snprintf(request, sizeof(request),
                                          "GET /extra/error HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://example.test\r\n\r\n");
                    if (requestLen <= 0 || static_cast<size_t>(requestLen) >= sizeof(request) || !sendAll(socketFd, request, requestLen) ||
                        !receiveHttpResponse(socketFd, response, sizeof(response)) || !strstr(response, "HTTP/1.1 400"))
                    {
                        goto done;
                    }
                    char* corsHeader = strstr(response, "Access-Control-Allow-Origin: https://example.test");

                    if ((!corsHeader) || strstr(corsHeader + 1, "Access-Control-Allow-Origin:"))
                    {
                        goto done;
                    }
                    close(socketFd);
                    socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
                    if (socketFd < 0 || connect(socketFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
                    {
                        goto done;
                    }
                    requestLen = snprintf(request, sizeof(request),
                                          "GET /missing HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://example.test\r\n\r\n");
                    if (requestLen > 0 && static_cast<size_t>(requestLen) < sizeof(request) && sendAll(socketFd, request, requestLen) &&
                        receiveHttpResponse(socketFd, response, sizeof(response)) && strstr(response, "HTTP/1.1 404") &&
                        strstr(response, "Access-Control-Allow-Origin: https://example.test") &&
                        strstr(response, "Access-Control-Allow-Credentials: true") &&
                        strstr(response, "Access-Control-Allow-Methods: GET,POST,OPTIONS") &&
                        strstr(response, "Access-Control-Allow-Headers: Content-Type, Authorization"))
                    {
                        close(socketFd);
                        socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
                        if (socketFd < 0 || connect(socketFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
                        {
                            goto done;
                        }
                        requestLen = snprintf(request, sizeof(request),
                                              "GET /missing HTTP/1.1\r\nHost: 127.0.0.1\r\nBroken-Header\r\n\r\n");
                        if (requestLen > 0 && static_cast<size_t>(requestLen) < sizeof(request) && sendAll(socketFd, request, requestLen) &&
                            receiveHttpResponse(socketFd, response, sizeof(response)) && strstr(response, "HTTP/1.1 400") &&
                            !strstr(response, "Access-Control-Allow-Origin:"))
                        {
                            testCtx->clientErr = ESP_OK;
                        }
                    }
                }
            }
        }
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

static void wildcardCorsClientTask(void* arg)
{
    LoopbackTestContext_t* testCtx = static_cast<LoopbackTestContext_t*>(arg);
    struct sockaddr_in addr = {};
    char request[256];
    char response[512];
    int socketFd = -1;
    int requestLen;

    testCtx->clientErr = ESP_FAIL;
    socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (socketFd < 0)
    {
        goto done;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(18082);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(socketFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        goto done;
    }
    requestLen = snprintf(request, sizeof(request),
                          "GET /extra/wildcard HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://example.test\r\n\r\n");
    if (requestLen <= 0 || static_cast<size_t>(requestLen) >= sizeof(request) || !sendAll(socketFd, request, requestLen) ||
        !receiveHttpResponse(socketFd, response, sizeof(response)) || !strstr(response, "HTTP/1.1 200") ||
        !strstr(response, "Access-Control-Allow-Origin: *") || strstr(response, "Access-Control-Allow-Credentials") ||
        strstr(response, "Vary: Origin"))
    {
        goto done;
    }
    requestLen = snprintf(request, sizeof(request),
                          "OPTIONS /extra/wildcard HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://example.test\r\n"
                          "Access-Control-Request-Method: GET\r\n\r\n");
    if (requestLen <= 0 || static_cast<size_t>(requestLen) >= sizeof(request) || !sendAll(socketFd, request, requestLen) ||
        !receiveHttpResponse(socketFd, response, sizeof(response)) || !strstr(response, "HTTP/1.1 204") ||
        !strstr(response, "Access-Control-Allow-Origin: *") || strstr(response, "Access-Control-Allow-Credentials") ||
        strstr(response, "Vary: Origin"))
    {
        goto done;
    }
    testCtx->clientErr = ESP_OK;

done:
    if (socketFd >= 0)
    {
        close(socketFd);
    }
    xSemaphoreGive(testCtx->done);
    vTaskDelete(nullptr);
}

static void multiCoreRequestTask(void* arg)
{
    MultiCoreRequestTaskArgs_t* taskArgs = static_cast<MultiCoreRequestTaskArgs_t*>(arg);
    LoopbackTestContext_t* testCtx = taskArgs->testCtx;
    struct sockaddr_in addr = {};
    char response[256];
    constexpr char request[] = "GET /extra/multicore HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://example.test\r\n\r\n";
    int socketFd = -1;

    testCtx->multiCoreClientErr[taskArgs->index] = ESP_FAIL;
    testCtx->multiCoreClientCore[taskArgs->index] = xPortGetCoreID();
    xEventGroupSetBits(testCtx->multiCoreSync, taskArgs->readyBit);
    if ((xEventGroupWaitBits(testCtx->multiCoreSync, kMultiCoreStartBit, pdFALSE, pdTRUE, pdMS_TO_TICKS(10000)) & kMultiCoreStartBit) == 0)
    {
        goto done;
    }

    socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (socketFd < 0)
    {
        goto done;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(18081);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(socketFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || !sendAll(socketFd, request, sizeof(request) - 1) ||
        !receiveHttpResponse(socketFd, response, sizeof(response)) || !strstr(response, "HTTP/1.1 200") || !strstr(response, "extra") ||
        strstr(response, "Access-Control-Allow-Origin"))
    {
        goto done;
    }
    testCtx->multiCoreClientErr[taskArgs->index] = ESP_OK;

done:
    if (socketFd >= 0)
    {
        close(socketFd);
    }
    xEventGroupSetBits(testCtx->multiCoreSync, taskArgs->doneBit);
    vTaskDelete(nullptr);
}
