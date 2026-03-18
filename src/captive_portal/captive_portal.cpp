#include "iot_comm/captive_portal/captive_portal.h"

#include "iot_comm/mDNS/mDNS.h"
#include "iot_comm/provisioning/wifi.h"
#include "iot_comm/crypto/aes.h"
#include "iot_comm/crypto/hkdf.h"
#include "iot_comm/crypto/p256.h"
#include "http_helpers.h"
#include <cJSON.h>
#include <convert.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <growable_buffer.h>
#include <mutex.h>

#define MAX_BODY_SIZE 10240
#define MAX_QUERY_SIZE 1024

#define NONCE_SIZE 12
#define IV_SIZE 12
#define AES_KEY_SIZE 32
#define AES_GCM_TAG_SIZE 16

#define TAG "CaptivePortal"

// -----------------------------------------------------------------------------

typedef esp_err_t (*reqGetHandler)(httpd_req_t *req);
typedef esp_err_t (*reqPostHandler)(httpd_req_t *req);

typedef struct handlerInfo_s {
    const char     *uri;
    reqGetHandler  get;
    reqPostHandler post;
} handlerInfo_t;

// -----------------------------------------------------------------------------

static const char hkdfInfo[] = "iot-comm/provisioning/v1";

extern const uint8_t webui_index_html_start[]     asm("_binary_index_html_start");
extern const uint8_t webui_index_html_end[]       asm("_binary_index_html_end");
extern const uint8_t webui_assets_app_js_start[]  asm("_binary_app_js_start");
extern const uint8_t webui_assets_app_js_end[]    asm("_binary_app_js_end");
extern const uint8_t webui_assets_app_css_start[] asm("_binary_app_css_start");
extern const uint8_t webui_assets_app_css_end[]   asm("_binary_app_css_end");

// -----------------------------------------------------------------------------

static RWMutex rwNtx;
static CaptivePortalCredentialsHandler_t handler = nullptr;
static void *handlerCtx = nullptr;
static uint8_t serverEcdhPrivateKey[P256_PRIVATE_KEY_SIZE] = {0};
static char serverEcdhPublicKeyB64[P256_MAX_B64_PUBLIC_KEY_SIZE] = {0};
static bool setupRootUser = true;
static bool setupDeviceHostname = true;

// -----------------------------------------------------------------------------

static void capPortalDeinitNoLock();

static esp_err_t handleRoot(httpd_req_t *req);
static esp_err_t handleAppJs(httpd_req_t *req);
static esp_err_t handleAppCss(httpd_req_t *req);
static esp_err_t handleInitParams(httpd_req_t *req);
static esp_err_t handleScanNetworks(httpd_req_t *req);
static esp_err_t handleServerKey(httpd_req_t *req);
static esp_err_t handleProvision(httpd_req_t *req);

static esp_err_t redirectToRoot(httpd_req_t *req);
static esp_err_t sendSuccess(httpd_req_t *req);

static esp_err_t sendEmbeddedFile(httpd_req_t *req, const char *type, const uint8_t *start, const uint8_t *end);

// -----------------------------------------------------------------------------

esp_err_t capPortalInit(CaptivePortalConfig_t *config)
{
    AutoRWMutex lock(rwNtx, false);
    P256KeyPair_t keyPair;
    esp_err_t err;

    if (!(config && config->handler)) {
        return ESP_ERR_INVALID_ARG;
    }

    handler = config->handler;
    handlerCtx = config->handlerCtx;
    setupRootUser = config->setupRootUser;
    setupDeviceHostname = config->setupDeviceHostname;

    // Generate server ECDH key pair for captive portal payload decryption
    p256KeyPairInit(&keyPair);
    err = ecdhGeneratePair(&keyPair);
    if (err == ESP_OK) {
        err = p256SavePrivateKey(&keyPair, serverEcdhPrivateKey);
        if (err == ESP_OK) {
            size_t publicKeyLen = sizeof(serverEcdhPublicKeyB64);

            err = p256SavePublicKeyB64(&keyPair, serverEcdhPublicKeyB64, &publicKeyLen, false);
        }
    }
    p256KeyPairDone(&keyPair);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize captive portal. Error: %d", err);
        capPortalDeinitNoLock();
        return err;
    }

    // Done
    ESP_LOGI(TAG, "Captive portal initialized");
    return ESP_OK;
}

void capPortalDeinit()
{
    AutoRWMutex lock(rwNtx, false);

    capPortalDeinitNoLock();
}

esp_err_t capPortalHandleRequest(httpd_req_t *req)
{
    static const handlerInfo_t handlers[13] = {
        { "/",                    handleRoot,         nullptr },
        { "/assets/app.js",       handleAppJs,        nullptr },
        { "/assets/app.css",      handleAppCss,       nullptr },
        { "/init-params",         handleInitParams,   nullptr },
        { "/scan-networks",       handleScanNetworks, nullptr },
        { "/server-key",          handleServerKey,    nullptr },
        { "/provision",           nullptr,            handleProvision },
        { "/success.txt",         sendSuccess,        nullptr },
        { "/generate_204",        redirectToRoot,     nullptr },
        { "/redirect",            redirectToRoot,     nullptr },
        { "/hotspot-detect.html", redirectToRoot,     nullptr },
        { "/canonical.html",      redirectToRoot,     nullptr },
        { "/ncsi.txt",            redirectToRoot,     nullptr }
    };

    AutoRWMutex lock(rwNtx, true);
    esp_err_t err;

    if (!req) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!handler) {
        return ESP_ERR_INVALID_STATE;
    }

    for (size_t i = 0; i < sizeof(handlers) / sizeof(handlers[0]); i++) {
        if (strcmp(req->uri, handlers[i].uri) == 0) {
            switch (req->method) {
                case HTTP_GET:
                    if (!handlers[i].get) {
                        goto err_not_found;
                    }
                    err = httpSendDefaultCORS(req);
                    if (err == ESP_OK) {
                        err =  handlers[i].get(req);
                    }
                    return err;

                case HTTP_POST:
                    if (!handlers[i].post) {
                        goto err_not_found;
                    }
                    err = httpSendDefaultCORS(req);
                    if (err == ESP_OK) {
                        err =  handlers[i].post(req);
                    }
                    return err;

                case HTTP_OPTIONS:
                    if (!(handlers[i].get || handlers[i].post)) {
                        goto err_not_found;
                    }
                    return httpSendPreflightResponse(req);
            }
        }
    }

    // Not found
err_not_found:
    err = httpSendDefaultCORS(req);
    if (err != ESP_OK) {
        return err;
    }
    return httpSendNotFound(req);
}

// -----------------------------------------------------------------------------

static void capPortalDeinitNoLock()
{
    handler = nullptr;
    handlerCtx = nullptr;
    setupRootUser = true;
    setupDeviceHostname = true;
    memset(serverEcdhPrivateKey, 0, sizeof(serverEcdhPrivateKey));
    memset(serverEcdhPublicKeyB64, 0, sizeof(serverEcdhPublicKeyB64));
}

static esp_err_t handleRoot(httpd_req_t *req)
{
    esp_err_t err;

    err = sendEmbeddedFile(req, "text/html", webui_index_html_start, webui_index_html_end);
    return httpSendInternalErrorResponse(req, err, nullptr);
}

static esp_err_t handleAppJs(httpd_req_t *req)
{
    esp_err_t err;

    err = sendEmbeddedFile(req, "application/javascript", webui_assets_app_js_start, webui_assets_app_js_end);
    return httpSendInternalErrorResponse(req, err, nullptr);
}

static esp_err_t handleAppCss(httpd_req_t *req)
{
    esp_err_t err;

    err = sendEmbeddedFile(req, "text/css", webui_assets_app_css_start, webui_assets_app_css_end);
    return httpSendInternalErrorResponse(req, err, nullptr);
}

static esp_err_t handleInitParams(httpd_req_t *req)
{
    cJSON *jsonRoot = nullptr;
    char *jsonString = nullptr;
    esp_err_t err;

    jsonRoot = cJSON_CreateObject();
    if (!jsonRoot) {
err_nomem:
        err = ESP_ERR_NO_MEM;
        goto done;
    }

    if (
        (!cJSON_AddBoolToObject(jsonRoot, "setupRootUser", setupRootUser)) ||
        (!cJSON_AddBoolToObject(jsonRoot, "setupDeviceHostname", setupDeviceHostname))
    ) {
        goto err_nomem;
    }

    jsonString = cJSON_PrintUnformatted(jsonRoot);
    if (!jsonString) {
        goto err_nomem;
    }

    err = httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        err = httpd_resp_sendstr(req, jsonString);
    }

done:
    if (jsonString) {
        cJSON_free(jsonString);
    }
    if (jsonRoot) {
        cJSON_Delete(jsonRoot);
    }
    return httpSendInternalErrorResponse(req, err, nullptr);
}

static esp_err_t handleScanNetworks(httpd_req_t *req)
{
    wifi_ap_record_t *records = nullptr;
    uint16_t recordsCount = 0;
    cJSON *jsonRoot = nullptr, *jsonArray = nullptr;
    char *jsonString = nullptr;
    wifi_scan_config_t scanConfig;
    esp_err_t err;

    memset(&scanConfig, 0, sizeof(scanConfig));
    err = esp_wifi_scan_start(&scanConfig, true);
    if (err != ESP_OK) {
        goto done;
    }
    err = esp_wifi_scan_get_ap_num(&recordsCount);
    if (err != ESP_OK) {
        goto done;
    }
    if (recordsCount > 0) {
        records = (wifi_ap_record_t *)malloc((size_t)recordsCount * sizeof(wifi_ap_record_t));
        if (!records) {
err_nomem:
            err = ESP_ERR_NO_MEM;
            goto done;
        }
        err = esp_wifi_scan_get_ap_records(&recordsCount, records);
        if (err != ESP_OK) {
            goto done;
        }
    }

    // Create output
    jsonRoot = cJSON_CreateObject();
    if (!jsonRoot) {
        goto err_nomem;
    }
    jsonArray = cJSON_AddArrayToObject(jsonRoot, "networks");
    if (!jsonArray) {
        goto err_nomem;
    }

    for (uint16_t i = 0; i < recordsCount; ++i) {
        bool alreadyPresent = false;

        for (uint16_t j = 0; j < i; j++) {
            if (strcasecmp((char *)records[i].ssid, (char *)records[j].ssid) == 0) {
                alreadyPresent = true;
                break;
            }
        }

        if (!alreadyPresent) {
            cJSON *jsonObj;

            jsonObj = cJSON_CreateObject();
            if (!jsonObj) {
                goto err_nomem;
            }
            cJSON_AddItemToArray(jsonArray, jsonObj);

            if (
                (!cJSON_AddStringToObject(jsonObj, "ssid", (const char *)records[i].ssid)) ||
                (!cJSON_AddNumberToObject(jsonObj, "rssi", (double)records[i].rssi)) ||
                (!cJSON_AddBoolToObject(jsonObj, "public", records[i].authmode == WIFI_AUTH_OPEN ? 1 : 0))
            ) {
                goto err_nomem;
            }
        }
    }

    jsonString = cJSON_PrintUnformatted(jsonRoot);
    if (!jsonString) {
        goto err_nomem;
    }

    // Send response
    err = httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        err = httpd_resp_send(req, jsonString, strlen(jsonString));
    }

done:
    // Cleanup
    if (jsonString) {
        cJSON_free(jsonString);
    }
    if (jsonRoot) {
        cJSON_Delete(jsonRoot);
    }
    free(records);

    // Done
    return httpSendInternalErrorResponse(req, err, nullptr);
}

static esp_err_t handleServerKey(httpd_req_t *req)
{
    char responseBody[P256_MAX_B64_PUBLIC_KEY_SIZE + 32];
    esp_err_t err;

    err = httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        int n = snprintf(responseBody, sizeof(responseBody), "{\"publicKey\":\"%s\"}", serverEcdhPublicKeyB64);
        err = (n > 0) ? httpd_resp_send(req, responseBody, (size_t)n) : ESP_FAIL;
    }

    // Done
    return httpSendInternalErrorResponse(req, err, nullptr);
}

static esp_err_t handleProvision(httpd_req_t *req)
{
    GrowableBuffer_t rawBodyBuffer = GB_STATIC_INIT;
    GrowableBuffer_t encryptedPayloadBuffer = GB_STATIC_INIT;
    GrowableBuffer_t plaintextBuffer = GB_STATIC_INIT;
    P256KeyPair_t ecdhKeyPair;
    mbedtls_gcm_context aesCtx;
    uint8_t sharedSecret[P256_SHARED_SECRET_SIZE] = {0};
    uint8_t derivedAesKey[AES_KEY_SIZE] = {0};
    uint8_t clientPublicKey[P256_PUBLIC_KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t iv[IV_SIZE];
    cJSON *json = nullptr;
    char *clientPublicKeyValue, *nonceValue, *ivValue, *encryptedPayloadValue;
    char *wifiSsidValue, *wifiPasswordValue, *rootUserPublicKeyValue, *hostnameValue;
    CaptivePortalCredentials_t creds;
    size_t clientPublicKeyLen, nonceLen, ivLen, encryptedPayloadLen;
    size_t rootUserPublicKeyLen;
    size_t plaintextLen;
    esp_err_t err;

    // Get body
    if (req->content_len > MAX_BODY_SIZE) {
        return httpd_resp_send_err(req, HTTPD_413_CONTENT_TOO_LARGE, nullptr);
    }
    if (req->content_len == 0) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid provisioning data");
    }

    // Initialize
    memset(&creds, 0, sizeof(creds));
    p256KeyPairInit(&ecdhKeyPair);
    aesInit(&aesCtx);

    // Get body
    err = httpGetRequestBody(&rawBodyBuffer, req);
    if (err != ESP_OK) {
        goto done;
    }

    // Parse encrypted envelope JSON
    json = cJSON_ParseWithLength((const char*)rawBodyBuffer.buffer, rawBodyBuffer.used);
    if (!json) {
err_invalid_data:
        err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid provisioning data");
        goto done;
    }

    clientPublicKeyValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "clientPublicKey"));
    nonceValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "nonce"));
    ivValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "iv"));
    encryptedPayloadValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "encryptedPayload"));
    if ((!clientPublicKeyValue) || (!nonceValue) || (!ivValue) || (!encryptedPayloadValue)) {
        goto err_invalid_data;
    }

    clientPublicKeyLen = sizeof(clientPublicKey);
    nonceLen = sizeof(nonce);
    ivLen = sizeof(iv);
    encryptedPayloadLen = (strlen(encryptedPayloadValue) / 4 + 1) * 3;
    if (
        (!fromB64(clientPublicKeyValue, strlen(clientPublicKeyValue), false, clientPublicKey, &clientPublicKeyLen)) ||
        (!fromB64(nonceValue, strlen(nonceValue), false, nonce, &nonceLen)) ||
        (!fromB64(ivValue, strlen(ivValue), false, iv, &ivLen))
    ) {
        goto err_invalid_data;
    }
    if (
        (clientPublicKeyLen != sizeof(clientPublicKey)) || (nonceLen != sizeof(nonce)) || (ivLen != sizeof(iv)) ||
        (!p256ValidatePublicKey(clientPublicKey, sizeof(clientPublicKey)))
    ) {
        goto err_invalid_data;
    }

    // Get encrypted payload
    gbReset(&encryptedPayloadBuffer, false);
    if (!gbReserve(&encryptedPayloadBuffer, encryptedPayloadLen + 1)) {
err_no_mem:
        err = ESP_ERR_NO_MEM;
        goto done;
    }
    if (!fromB64(encryptedPayloadValue, strlen(encryptedPayloadValue), false,
                 encryptedPayloadBuffer.buffer, &encryptedPayloadLen)) {
        goto err_invalid_data;
    }
    if (encryptedPayloadLen < AES_GCM_TAG_SIZE) {
        goto err_invalid_data;
    }
    encryptedPayloadBuffer.used = encryptedPayloadLen;

    // Decrypt payload: ECDH shared secret -> HKDF-SHA256 key -> AES-GCM decrypt
    err = p256LoadPrivateKey(&ecdhKeyPair, serverEcdhPrivateKey);
    if (err == ESP_OK) {
        err = p256LoadPublicKey(&ecdhKeyPair, clientPublicKey);
        if (err == ESP_OK) {
            err = ecdhComputeSharedSecret(&ecdhKeyPair, sharedSecret);
            if (err == ESP_OK) {
                err = hkdfSha256DeriveKey(sharedSecret, sizeof(sharedSecret), nonce, sizeof(nonce), (const uint8_t *)hkdfInfo,
                                          sizeof(hkdfInfo) - 1, derivedAesKey, sizeof(derivedAesKey));
                if (err == ESP_OK) {
                    err = aesSetKey(&aesCtx, derivedAesKey, sizeof(derivedAesKey));
                }
            }
        }
    }
    if (err != ESP_OK) {
        goto done;
    }

    plaintextLen = encryptedPayloadLen - AES_GCM_TAG_SIZE;
    gbReset(&plaintextBuffer, false);
    if (!gbReserve(&plaintextBuffer, plaintextLen + 1)) {
        goto err_no_mem;
    }
    err = aesDecrypt(&aesCtx, encryptedPayloadBuffer.buffer, encryptedPayloadLen, iv, sizeof(iv), nullptr, 0, plaintextBuffer.buffer);
    if (err != ESP_OK) {
        err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Unable to decrypt provisioning payload");
        goto done;
    }
    plaintextBuffer.used = plaintextLen;
    plaintextBuffer.buffer[plaintextLen] = 0;

    // Parse decrypted payload
    cJSON_Delete(json);
    json = cJSON_ParseWithLength((char *)plaintextBuffer.buffer, plaintextLen);
    if (!json) {
        goto err_invalid_data;
    }

    wifiSsidValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "wifiSSID"));
    wifiPasswordValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "wifiPassword"));
    rootUserPublicKeyValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "rootUserPublicKey"));
    hostnameValue = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "hostname"));
    if ((!wifiSsidValue) || (!wifiPasswordValue)) {
        goto err_invalid_data;
    }

    if (*wifiSsidValue == 0 || strlen(wifiSsidValue) > 32) {
        err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID must be 1..32 characters.");
        goto done;
    }
    strlcpy(creds.wifiSSID, wifiSsidValue, sizeof(creds.wifiSSID));

    if (*wifiPasswordValue != 0 && (strlen(wifiPasswordValue) < 8 || strlen(wifiPasswordValue) > 64)) {
        err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Password must be empty or 8..64 characters.");
        goto done;
    }
    strlcpy(creds.wifiPassword, wifiPasswordValue, sizeof(creds.wifiPassword));

    if (setupRootUser) {
        if (!rootUserPublicKeyValue) {
            goto err_invalid_data;
        }

        rootUserPublicKeyLen = sizeof(creds.rootUserPublicKey);
        if (
            (!fromB64(rootUserPublicKeyValue, strlen(rootUserPublicKeyValue), false, creds.rootUserPublicKey, &rootUserPublicKeyLen)) ||
            (!p256ValidatePublicKey(creds.rootUserPublicKey, rootUserPublicKeyLen))
        ) {
            err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Root user key must be valid Base64 and decode to exactly 65 bytes.");
            goto done;
        }
    }

    if (setupDeviceHostname) {
        if (!hostnameValue) {
            goto err_invalid_data;
        }

        if (*hostnameValue != 0 && !mDnsIsValidHostname(hostnameValue)) {
            err = httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Hostname must be RFC1123 compliant.");
            goto done;
        }

        strlcpy(creds.hostname, hostnameValue, sizeof(creds.hostname));
    }

    // Call callback
    err = handler(&creds, handlerCtx);
    if (err != ESP_OK) {
        goto done;
    }

    // Send response
    err = sendSuccess(req);

done:
    // Cleanup
    if (json) {
        cJSON_Delete(json);
        json = nullptr;
    }
    memset(sharedSecret, 0, sizeof(sharedSecret));
    memset(derivedAesKey, 0, sizeof(derivedAesKey));
    gbWipe(&plaintextBuffer);
    gbWipe(&encryptedPayloadBuffer);
    gbWipe(&rawBodyBuffer);
    gbReset(&plaintextBuffer, true);
    gbReset(&encryptedPayloadBuffer, true);
    gbReset(&rawBodyBuffer, true);
    aesDone(&aesCtx);
    p256KeyPairDone(&ecdhKeyPair);

    // Done
    return httpSendInternalErrorResponse(req, err, nullptr);
}

static esp_err_t redirectToRoot(httpd_req_t *req)
{
    char szUri[32];
    uint8_t ip[4];
    esp_err_t err;

    wifiMgrGetApIPAddress(ip);
    snprintf(szUri, sizeof(szUri), "http://%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

    err = httpd_resp_set_status(req, "302 Found");
    if (err == ESP_OK) {
        err = httpd_resp_set_hdr(req, "Location", szUri);
        if (err == ESP_OK) {
            err = httpd_resp_send(req, nullptr, 0);
        }
    }

    // Done
    return err;
}

static esp_err_t sendSuccess(httpd_req_t *req)
{
    esp_err_t err;

    err = httpd_resp_set_status(req, "200 OK");
    if (err == ESP_OK) {
        err = httpd_resp_send(req, nullptr, 0);
    }

    // Done
    return err;
}

static esp_err_t sendEmbeddedFile(httpd_req_t *req, const char *type, const uint8_t *start, const uint8_t *end)
{
    esp_err_t err;

    err = httpd_resp_set_type(req, type);
    if (err == ESP_OK) {
        err = httpd_resp_send(req, (const char *)start, (size_t)(end - start));
    }
    return err;
}
