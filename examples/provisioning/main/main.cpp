#include <esp_err.h>
#include <iot_comm/iot_comm.h>
#include <iot_comm/captive_portal/captive_portal.h>
#include <iot_comm/provisioning/wifi.h>
#include <mdns.h>
#include <rundown_protection.h>
#include <run_once.h>

// -----------------------------------------------------------------------------

static void setupTask(void *arg);

static void iotCommEventHandler(IotCommEvent_t event, void *eventData);
static void wifiMgrEventHandler(WifiMgrEvent_t event, void *ctx);
static esp_err_t captivePortalCredentialsHandler(CaptivePortalCredentials_t *creds, void *ctx);
static esp_err_t loadUsersFromStorage(void *dest, size_t destLen, void *ctx);
static esp_err_t saveUsersToStorage(const void *data, size_t dataLen, void *ctx);

// -----------------------------------------------------------------------------

extern "C" void app_main()
{
    TaskHandle_t setupTaskHandle;

    ESP_ERROR_CHECK((xTaskCreatePinnedToCore(setupTask, "setupTask", 4096, NULL, 1, &setupTaskHandle, 0) == pdPASS
                     ? ESP_OK : ESP_ERR_NO_MEM));
}

static void setupTask(void *arg)
{
    IotCommConfig_t iotCommConfig;
    WifiMgrConfig_t wifiConfig;

    iotCommConfig = iotCommDefaultConfig();
    iotCommConfig.handler = iotCommEventHandler;
    iotCommConfig.storage.load = loadUsersFromStorage;
    iotCommConfig.storage.save = saveUsersToStorage;
    ESP_ERROR_CHECK(iotCommInit(&iotCommConfig));

    memset(&wifiConfig, 0, sizeof(wifiConfig));
    wifiConfig.handler = wifiMgrEventHandler;
    wifiConfig.softAP.ssid = "iotcomm-network";
    wifiConfig.softAP.captivePortal.init = [](void *) -> esp_err_t
    {
        CaptivePortalConfig_t capPortalConfig = {};

        capPortalConfig.handler = captivePortalCredentialsHandler;
        capPortalConfig.setupRootUser = true;
        capPortalConfig.setupDeviceHostname = true;
        return capPortalInit(&capPortalConfig);
    };
    wifiConfig.softAP.captivePortal.done = [](void *) -> void
    {
        capPortalDeinit();
    };
    wifiConfig.softAP.captivePortal.httpReq = [](httpd_req_t *req, void *) -> esp_err_t
    {
        return capPortalHandleRequest(req);
    };

    ESP_ERROR_CHECK(wifiMgrInit(&wifiConfig));
    ESP_ERROR_CHECK(mdns_init());

    vTaskDelete(nullptr);
}

static void iotCommEventHandler(IotCommEvent_t event, void *eventData)
{

}

static void wifiMgrEventHandler(WifiMgrEvent_t event, void *ctx)
{

}

static esp_err_t captivePortalCredentialsHandler(CaptivePortalCredentials_t *creds, void *ctx)
{
    esp_err_t err;

    err = iotCommInitRootUserPublicKey(creds->rootUserPublicKey);
    if (err == ESP_OK && *creds->hostname != 0) {
        err = mdns_hostname_set(creds->hostname);
    }
    if (err == ESP_OK) {
        err = wifiMgrStoreSTA(creds->wifiSSID, creds->wifiPassword);
    }
    if (err == ESP_OK) {
        err = wifiMgrStartSTA();
    }
    return err;
}

static esp_err_t loadUsersFromStorage(void *dest, size_t destLen, void *ctx)
{
    // We return not found because we always initialize as empty
    return ESP_ERR_NOT_FOUND;
}

static esp_err_t saveUsersToStorage(const void *data, size_t dataLen, void *ctx)
{
    // This demo does not store anything
    return ESP_OK;
}
