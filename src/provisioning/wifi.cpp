#include "iot_comm/provisioning/wifi.h"
#include <esp_event.h>
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <mutex.h>
#include <network_provisioning/manager.h>
#include <network_provisioning/scheme_ble.h> // BLE transport
#include <rundown_protection.h>
#include <string.h>

static const char* TAG = "WIFI-PROV";

// -----------------------------------------------------------------------------

static RundownProtection_t rp = RUNDOWN_PROTECTION_INIT_STATIC;
static Mutex mtx;

static char provider[32 + 1 + 6 + 1] = {0};
static char popCode[32 + 1] = {0};
static uint8_t bleServiceUUID[16];
static WifiMgrEventHandler_t handler = nullptr;
static bool connected = false;

// -----------------------------------------------------------------------------

static void startProvisioningIfNeeded(WifiMgrConfig_t *config);
static void onEvent(void *arg, esp_event_base_t eventBase, int32_t eventId, void *eventData);
static void setConnectedStateAndCallCallback(bool isConnected);

// -----------------------------------------------------------------------------

void wifiMgrInit(WifiMgrConfig_t *config)
{
    AutoMutex lock(&mtx);

    assert(config);
    assert((!config->providerPrefix) || strlen(config->providerPrefix) <= 32);
    assert((!config->popCode) || strlen(config->popCode) <= 32);
    assert(config->handler);

    handler = config->handler;

    // Start provisioning if needed (or start STA if already provisioned)
    startProvisioningIfNeeded(config);

    ESP_LOGI(TAG, "Wi-Fi manager sucessfully initialized.");
}

void wifiMgrDone()
{
    AutoMutex lock(&mtx);

    rundownProtWait(&rp);

    if (handler != nullptr) {
        esp_wifi_disconnect();
        esp_wifi_stop();

        esp_wifi_deinit();
        network_prov_mgr_deinit();

        handler = nullptr;
        connected = false;
        memset(provider, 0, sizeof(provider));
        memset(popCode, 0, sizeof(popCode));
        memset(bleServiceUUID, 0, sizeof(bleServiceUUID));
    }

    rundownProtInit(&rp);
}

bool wifiMgrDeleteConfig()
{
    AutoRundownProtection rpLock(&rp);

    if (!rpLock.acquired()) {
        return false;
    }

    network_prov_mgr_reset_wifi_provisioning();
    return true;
}

// -----------------------------------------------------------------------------

static void startProvisioningIfNeeded(WifiMgrConfig_t *config)
{
    network_prov_mgr_config_t providerConfig;
    bool provisioned = false;

    // Initialize TCP/IP
    ESP_ERROR_CHECK(esp_netif_init());

    // Create default event loop (Arduino usually has it, but this is safe)
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Initialize Wi-Fi including netif with default config
    esp_netif_t *wifiNetIf = esp_netif_create_default_wifi_sta();

    // Register handlers for provisioning / Wi-Fi / IP events
    ESP_ERROR_CHECK(esp_event_handler_register(NETWORK_PROV_EVENT, ESP_EVENT_ANY_ID, &onEvent, wifiNetIf));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &onEvent, nullptr));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &onEvent, nullptr));

    // Initialize Wi-Fi including netif with default config
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Initialize provisioning manager with BLE scheme
    memset(&providerConfig, 0, sizeof(providerConfig));
    providerConfig.scheme = network_prov_scheme_ble;
    providerConfig.scheme_event_handler = NETWORK_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM;
    ESP_ERROR_CHECK(network_prov_mgr_init(providerConfig));

    ESP_ERROR_CHECK(network_prov_mgr_is_wifi_provisioned(&provisioned));

    if (!provisioned) {
        // Not provisioned yet -> start BLE provisioning
        network_prov_security_t security = NETWORK_PROV_SECURITY_0;
        network_prov_security1_params_t *secParams = nullptr;
        uint8_t macAddr[6];

        ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, macAddr));
        ESP_LOGI(TAG, "MAC Address: %02X:%02X:%02X:%02X:%02X:%02X",
                macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);

        snprintf(provider, sizeof(provider), "%s_%02X%02X%02X",
                ((config->providerPrefix && config->providerPrefix[0] != 0) ? config->providerPrefix : "PROV"),
                macAddr[3], macAddr[4], macAddr[5]);

        // This step is only useful when scheme is network_prov_scheme_ble. This will
        // set a custom 128 bit UUID which will be included in the BLE advertisement
        // and will correspond to the primary GATT service that provides provisioning
        // endpoints as GATT characteristics. Each GATT characteristic will be
        // formed using the primary service UUID as base, with different auto assigned
        // 12th and 13th bytes (assume counting starts from 0th byte). The client side
        // applications must identify the endpoints by reading the User Characteristic
        // Description descriptor (0x2901) for each characteristic, which contains the
        // endpoint name of the characteristic
        memcpy(bleServiceUUID, config->bleServiceUUID, sizeof(bleServiceUUID));
        ESP_ERROR_CHECK(network_prov_scheme_ble_set_service_uuid(bleServiceUUID));

        // Security 1 with POP (recommended)
        if (config->popCode && config->popCode[0] != 0) {
            strcpy(popCode, config->popCode);

            security = NETWORK_PROV_SECURITY_1;
            secParams = (network_prov_security1_params_t *)popCode;
        }

        // Start provisioning service
        ESP_ERROR_CHECK(network_prov_mgr_start_provisioning(security, (const void *)secParams, provider, nullptr));
    }
    else {
        // Already provisioned -> we can stop the manager
        network_prov_mgr_deinit();

        // And start Wi-Fi in station mode
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        ESP_ERROR_CHECK(esp_wifi_start());
    }

    // Disable power saving mode (a reason for ping delays and network latency)
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
}

static void onEvent(void *arg, esp_event_base_t eventBase, int32_t eventId, void *eventData)
{
    if (eventBase == NETWORK_PROV_EVENT) {
        switch (eventId) {
            case NETWORK_PROV_START:
                ESP_LOGI(TAG, "Wi-Fi Provisioning started.");
                break;

            case NETWORK_PROV_WIFI_CRED_RECV:
                {
                    wifi_sta_config_t *wifi_sta_cfg = (wifi_sta_config_t *)eventData;

                    ESP_LOGI(TAG, "Received Wi-Fi credentials. SSID: %s", (const char *)wifi_sta_cfg->ssid);
                }
                break;

            case NETWORK_PROV_WIFI_CRED_FAIL:
                {
                    network_prov_wifi_sta_fail_reason_t *reason = (network_prov_wifi_sta_fail_reason_t *)eventData;

                    ESP_LOGI(TAG, "Wi-Fi provisioning failed! Reason: %s.", ((*reason == NETWORK_PROV_WIFI_STA_AUTH_ERROR) ? "Authentication failed" : "Access-point not found"));
                }
                break;

            case NETWORK_PROV_WIFI_CRED_SUCCESS:
                ESP_LOGI(TAG, "Wi-Fi provisioning succeeded!");
                break;

            case NETWORK_PROV_END:
                // De-initialize manager once provisioning is finished
                network_prov_mgr_deinit();
                break;
        }
    }
    else if (eventBase == WIFI_EVENT) {
        switch (eventId) {
            case WIFI_EVENT_STA_START:
                {
                    AutoRundownProtection rpLock(&rp);

                    if (rpLock.acquired()) {
                        esp_wifi_connect();
                    }
                }
                break;

            case WIFI_EVENT_STA_DISCONNECTED:
                ESP_LOGI(TAG, "Wi-Fi disconnected. Trying to re-connect to the AP...");

                {
                    AutoRundownProtection rpLock(&rp);

                    if (rpLock.acquired()) {
                        setConnectedStateAndCallCallback(false);
                        esp_wifi_connect();
                    }
                }
                break;
        }
    }
    else if (eventBase == IP_EVENT) {
        switch (eventId) {
            case IP_EVENT_STA_GOT_IP:
                {
                    ip_event_got_ip_t *event = (ip_event_got_ip_t *)eventData;

                    ESP_LOGI(TAG, "Wi-Fi connected. IPv4 address: " IPSTR, IP2STR(&event->ip_info.ip));

                    {
                        AutoRundownProtection rpLock(&rp);

                        if (rpLock.acquired()) {
                            setConnectedStateAndCallCallback(true);
                        }
                    }
                }
                break;

            case IP_EVENT_GOT_IP6:
                {
                    ip_event_got_ip6_t *event = (ip_event_got_ip6_t *)eventData;

                    ESP_LOGI(TAG, "Wi-Fi connected. IPv6 address: " IPV6STR, IPV62STR(event->ip6_info.ip));

                    {
                        AutoRundownProtection rpLock(&rp);

                        if (rpLock.acquired()) {
                            setConnectedStateAndCallCallback(true);
                        }
                    }
                }
                break;
        }
    }
}

static void setConnectedStateAndCallCallback(bool isConnected)
{
    if (isConnected != connected) {
        connected = isConnected;
        if (connected) {
            handler(WifiMgrEventConnected);
        }
        else {
            handler(WifiMgrEventDisconnected);
        }
    }
}
