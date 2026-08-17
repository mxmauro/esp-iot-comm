#include <esp_err.h>
#include <esp_log.h>
#include <esp_mac.h>
#include <iot_comm/iot_comm.h>
#include <iot_comm/captive_portal/captive_portal.h>
#include <iot_comm/provisioning/wifi.h>
#include <mdns.h>
#include <rundown_protection.h>
#include <run_once.h>
#include <storage/nvs.h>

static const char *TAG = "MAIN";

// -----------------------------------------------------------------------------

static NVSStorage storage;

// -----------------------------------------------------------------------------

static void setupTask(void *arg);

static void iotCommEventHandler(IotCommEvent_t *event);
static void wifiMgrEventHandler(WifiMgrEvent_t event, void *ctx);
static esp_err_t captivePortalCredentialsHandler(CaptivePortalProvisioningConfig_t *creds, void *ctx);

static esp_err_t loadFromStorage(IotCommStorageItemType_t itemType, void *dest, size_t destLen, void *ctx);
static esp_err_t saveToStorage(IotCommStorageItemType_t itemType, const void *data, size_t dataLen, void *ctx);

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
    char ssid[32];
    uint8_t mac[6];

    iotCommConfig = iotCommDefaultConfig();
    iotCommConfig.handler = iotCommEventHandler;
    iotCommConfig.storage.load = loadFromStorage;
    iotCommConfig.storage.save = saveToStorage;
    ESP_ERROR_CHECK(iotCommInit(&iotCommConfig));

    ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP));
    snprintf(ssid, sizeof(ssid), "iotcomm-network-%02X%02X", mac[4], mac[5]);

    memset(&wifiConfig, 0, sizeof(wifiConfig));
    wifiConfig.handler = wifiMgrEventHandler;
    wifiConfig.maxWifiPower = 8.5f; // To get rid of the ESP32-C3 bad "antenna" design.
    wifiConfig.softAP.ssid = ssid;
    wifiConfig.softAP.captivePortal.init = [](void *) -> esp_err_t
    {
        CaptivePortalConfig_t capPortalConfig = {};

        capPortalConfig.handler = captivePortalCredentialsHandler;
        capPortalConfig.setupRootUser = true;
        capPortalConfig.setupDeviceHostname = true;
        return capPortalInit(&capPortalConfig);
    };
    wifiConfig.softAP.captivePortal.deinit = [](void *) -> void
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

static void iotCommEventHandler(IotCommEvent_t *)
{

}

static void wifiMgrEventHandler(WifiMgrEvent_t event, void *)
{
    switch (event) {
        case WifiMgrEventConnected:
            {
                IotCommServerConfig_t iotCommServerConfig;
                esp_err_t err;

                iotCommServerConfig = iotCommDefaultServerConfig();
                iotCommServerConfig.udpListenPort = 32888;
                err = iotCommStartServer(&iotCommServerConfig);
                if (err != ESP_OK) {
                    ESP_LOGE(TAG, "Unable to start Iot-Comm server. Err: %d.", err);
                }
            }
            break;

        case WifiMgrEventDisconnected:
            iotCommStopServer();
            break;

        case WifiMgrEventAuthenticationFailed:
            break;
    }
}

static esp_err_t captivePortalCredentialsHandler(CaptivePortalProvisioningConfig_t *creds, void *)
{
    esp_err_t err;

    err = iotCommInitRootUserPublicKey(creds->rootUserPublicKey);
    if (err == ESP_OK && creds->hostname[0] != 0) {
        err = mdns_hostname_set(creds->hostname);
    }
    if (err == ESP_OK) {
        err = wifiMgrSetHostname(creds->hostname[0] != 0 ? creds->hostname : nullptr);
    }
    if (err == ESP_OK) {
        err = wifiMgrStoreSTA(creds->wifiSSID, creds->wifiPassword);
    }
    if (err == ESP_OK) {
        err = wifiMgrStartSTA();
    }
    return err;
}

static esp_err_t loadFromStorage(IotCommStorageItemType_t itemType, void *dest, size_t destLen, void *)
{
    lightstd::vector<uint8_t> data;
    esp_err_t err;

    switch (itemType) {
        case IotCommStorageItemTypeUsers:
            err = storage.readBlob("users", data);
            break;

        case IotCommStorageItemTypeDeviceIdentityKeyPair:
            err = storage.readBlob("deviceID", data);
            break;

        default:
            return ESP_FAIL;
    }
    if (err != ESP_OK) {
        return err;
    }
    if (data.size() != destLen) {
        return ESP_FAIL;
    }

    memcpy(dest, data.data(), destLen);
    return ESP_OK;
}

static esp_err_t saveToStorage(IotCommStorageItemType_t itemType, const void *data, size_t dataLen, void *)
{
    esp_err_t err;

    switch (itemType) {
        case IotCommStorageItemTypeUsers:
            err = storage.writeBlob("users", data, dataLen);
            if (err != ESP_OK) {
                return err;
            }
            return storage.commit();

        case IotCommStorageItemTypeDeviceIdentityKeyPair:
            err = storage.writeBlob("deviceID", data, dataLen);
            if (err != ESP_OK) {
                return err;
            }
            return storage.commit();

        default:
            return ESP_FAIL;
    }
}
