#include "iot_comm/provisioning/wifi.h"
#include "iot_comm/utils/network.h"
#include <esp_check.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_netif_ip_addr.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <esp_wifi.h>
#include <lwip/sockets.h>
#include <mutex.h>
#include <nvs_flash.h>
#include <rundown_protection.h>
#include <storage/nvs.h>
#include <string.h>
#include <task.h>

static const char *TAG = "WIFI-PROV";
static const char *NVSNamespace = "iotcomm-wifi";
static const char *NVSKeyHostname = "hostname";

#define STA_TRANSITION_DELAY_US 150000

// -----------------------------------------------------------------------------

typedef struct dhcps_lease_s {
    bool enable;
    ip4_addr_t start_ip;
    ip4_addr_t end_ip;
} dhcps_lease_t;

// -----------------------------------------------------------------------------

static RundownProtection_t rp = RUNDOWN_PROTECTION_INIT_STATIC;
static Mutex mtx;
static Mutex cpDnsMtx;

static esp_netif_t *defNetIfWifiSta = nullptr;
static esp_netif_t *defNetIfWifiAp = nullptr;

static bool provisioned = false;

static httpd_handle_t cpHttpServer = nullptr;
static WifiMgrCaptivePortalDeinitCallback_t cpDeinitHandler = nullptr;
static WifiMgrCaptivePortalHttpRequestHandler_t cpHttpReqHandler = nullptr;
static void *cpHandlerCtx = nullptr;

static Task_t cpDnsTask = TASK_INIT_STATIC;
static int cpDnsSocket = -1;
static uint8_t cpDnsIP[4] = {0};

static char cpDhcpUri[32] = {0};

static WifiMgrEventHandler_t handler = nullptr;
static void *handlerCtx = nullptr;
static bool connected = false;
static bool staTransitionPending = false;
static esp_timer_handle_t staTransitionTimer = nullptr;
static float maxWifiPower = 0.0f;

// -----------------------------------------------------------------------------

static void wifiMgrDeinitNoLock();
static esp_err_t initNetworkAndProvisioning(WifiMgrConfig_t *config);
static void onEvent(void *arg, esp_event_base_t eventBase, int32_t eventId, void *eventData);
static void staTransitionTimerCallback(void *arg);
static void performStaModeTransition();
static esp_err_t setWifiTxPower(float power);
static esp_err_t loadStoredHostnameOrDefault(char hostname[MAX_HOSTNAME_LEN + 1]);
static esp_err_t saveStoredHostname(const char *hostname);
static esp_err_t eraseStoredHostname();
static esp_err_t setCustomAddressInAP(esp_netif_t *netIf);
static esp_err_t setNetifHostname(esp_netif_t *netIf, const char *hostname);
static esp_err_t captivePortalSetupDhcpUrl();
static esp_err_t captivePortalSetupDns();
static esp_err_t captivePortalCatchAllHandler(httpd_req_t *req);
static void cpDnsServerTask(Task_t *task, void *arg);
static void stopCaptivePortal();

// -----------------------------------------------------------------------------

esp_err_t wifiMgrInit(WifiMgrConfig_t *config)
{
    AutoMutex lock(mtx);
    esp_err_t err;

    if (!(config && config->handler)) {
        return ESP_ERR_INVALID_ARG;
    }
    if ((!config->softAP.ssid) || config->softAP.ssid[0] == 0 || strlen(config->softAP.ssid) >= sizeof(((wifi_config_t *)0)->ap.ssid)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (config->softAP.password && strlen(config->softAP.password) >= sizeof(((wifi_config_t *)0)->ap.password)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!config->softAP.captivePortal.httpReq) {
        return ESP_ERR_INVALID_ARG;
    }

    wifiMgrDeinitNoLock();

    handler = config->handler;
    handlerCtx = config->handlerCtx;

    err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        err = nvs_flash_erase();
        if (err == ESP_OK) {
            err = nvs_flash_init();
        }
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize NVS. Error: %d.", err);
        wifiMgrDeinitNoLock();
        return err;
    }

    err = initNetworkAndProvisioning(config);
    if (err != ESP_OK) {
        wifiMgrDeinitNoLock();
        return err;
    }

    ESP_LOGI(TAG, "Manager initialized successfully.");
    return ESP_OK;
}

void wifiMgrDeinit()
{
    rundownProtWait(&rp);

    {
        AutoMutex lock(mtx);

        wifiMgrDeinitNoLock();
    }
}

bool wifiMgrIsProvisioned()
{
    AutoMutex lock(mtx);

    return provisioned;
}

bool wifiMgrDeleteConfig()
{
    AutoMutex lock(mtx);
    AutoRundownProtection rpLock(rp);
    esp_err_t err;

    if (!rpLock.acquired() || (!handler)) {
        return false;
    }

    if (staTransitionPending && staTransitionTimer) {
        esp_timer_stop(staTransitionTimer);
        staTransitionPending = false;
    }

    err = esp_wifi_restore();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to erase the stored configuration. Error: %d.", err);
        return false;
    }

    provisioned = false;
    return true;
}

esp_err_t wifiMgrSetHostname(const char *hostname)
{
    AutoMutex lock(mtx);
    esp_err_t err;

    if (hostname && *hostname != 0 && (!isValidHostname(hostname))) {
        return ESP_ERR_INVALID_ARG;
    }

    err = (hostname && *hostname != 0) ? saveStoredHostname(hostname) : eraseStoredHostname();
    if (err != ESP_OK) {
        return err;
    }

    if (defNetIfWifiSta) {
        err = setNetifHostname(defNetIfWifiSta, hostname);
        if (err != ESP_OK) {
            return err;
        }
    }
    if (defNetIfWifiAp) {
        err = setNetifHostname(defNetIfWifiAp, hostname);
        if (err != ESP_OK) {
            return err;
        }
    }

    return ESP_OK;
}

esp_err_t wifiMgrGetHostname(char hostname[MAX_HOSTNAME_LEN + 1])
{
    AutoMutex lock(mtx);

    if (!hostname) {
        return ESP_ERR_INVALID_ARG;
    }
    return loadStoredHostnameOrDefault(hostname);
}

esp_err_t wifiMgrStoreSTA(const char *ssid, const char *password)
{
    AutoMutex lock(mtx);
    wifi_config_t staConfig;

    // Verify parameters
    if ((!ssid) || *ssid == 0 || strlen(ssid) >= sizeof(staConfig.sta.ssid)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (password && strlen(password) >= sizeof(staConfig.sta.password)) {
        return ESP_ERR_INVALID_ARG;
    }

    // Is the provisioning module running?
    if (!(handler && cpHttpServer)) {
        return ESP_ERR_INVALID_STATE;
    }

    // Build configuration
    memset(&staConfig, 0, sizeof(staConfig));
    strlcpy((char *)staConfig.sta.ssid, ssid, sizeof(staConfig.sta.ssid));
    if (password && password[0] != 0) {
        strlcpy((char *)staConfig.sta.password, password, sizeof(staConfig.sta.password));
        staConfig.sta.threshold.authmode = WIFI_AUTH_WPA2_WPA3_PSK;
    }
    else {
        staConfig.sta.threshold.authmode = WIFI_AUTH_OPEN;
    }
    staConfig.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;  // More thorough scanning
    staConfig.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    staConfig.sta.pmf_cfg.capable = true;
    staConfig.sta.pmf_cfg.required = false;

    ESP_RETURN_ON_ERROR(esp_wifi_set_storage(WIFI_STORAGE_FLASH), TAG, "Failed to select flash storage");
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &staConfig), TAG, "Failed to configure STA mode");

    // Done
    provisioned = true;
    return ESP_OK;
}

esp_err_t wifiMgrStartSTA()
{
    AutoMutex lock(mtx);
    esp_err_t err;

    // Check current state
    if (!(handler && cpHttpServer)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!provisioned) {
        return ESP_ERR_INVALID_STATE;
    }
    if (staTransitionPending) {
        return ESP_ERR_INVALID_STATE;
    }

    // Run delayed transitioner
    if (!staTransitionTimer) {
        esp_timer_create_args_t timerArgs;

        memset(&timerArgs, 0, sizeof(timerArgs));
        timerArgs.callback = &staTransitionTimerCallback;
        timerArgs.dispatch_method = ESP_TIMER_TASK;
        timerArgs.name = "iotcomm-wifi_sta_sw";
        err = esp_timer_create(&timerArgs, &staTransitionTimer);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to create the STA transition timer. Error: %d.", err);
            return err;
        }
    }

    staTransitionPending = true;
    err = esp_timer_start_once(staTransitionTimer, STA_TRANSITION_DELAY_US);
    if (err != ESP_OK) {
        staTransitionPending = false;
        ESP_LOGE(TAG, "Failed to start the STA transition timer. Error: %d.", err);
        return err;
    }

    // Done
    return ESP_OK;
}

esp_err_t wifiMgrGetApIPAddress(uint8_t ip[4])
{
    AutoMutex lock(mtx);

    if (!(handler && cpHttpServer)) {
        memset(ip, 0, 4);
        return ESP_ERR_INVALID_STATE;
    }

    memcpy(ip, cpDnsIP, 4);
    return ESP_OK;
}

static void wifiMgrDeinitNoLock()
{
    if (staTransitionTimer) {
        esp_timer_stop(staTransitionTimer);
        esp_timer_delete(staTransitionTimer);
        staTransitionTimer = nullptr;
    }
    staTransitionPending = false;

    if (handler != nullptr) {
        stopCaptivePortal();

        esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &onEvent);
        esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &onEvent);
        esp_event_handler_unregister(IP_EVENT, IP_EVENT_GOT_IP6, &onEvent);

        esp_wifi_disconnect();
        esp_wifi_stop();

        if (defNetIfWifiAp) {
            esp_netif_destroy_default_wifi(defNetIfWifiAp);
            defNetIfWifiAp = nullptr;
        }
        if (defNetIfWifiSta) {
            esp_netif_destroy_default_wifi(defNetIfWifiSta);
            defNetIfWifiSta = nullptr;
        }

        esp_wifi_deinit();

        handler = nullptr;
        handlerCtx = nullptr;
    }

    maxWifiPower = 0.0f;
    connected = false;
    provisioned = false;

    rundownProtInit(&rp);
}

static esp_err_t initNetworkAndProvisioning(WifiMgrConfig_t *config)
{
    wifi_init_config_t cfg;
    wifi_config_t staConfig;
    char hostname[MAX_HOSTNAME_LEN + 1];
    esp_err_t err;

    // Initialize network interface engine
    ESP_RETURN_ON_ERROR(esp_netif_init(), TAG, "Failed to initialize the TCP/IP stack");

    // Create default event loop if not done yet
    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Failed to create the default event loop. Error: %d.", err);
        return err;
    }

    err = loadStoredHostnameOrDefault(hostname);
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
        ESP_LOGE(TAG, "Failed to read the configured hostname. Error: %d.", err);
        return err;
    }

    // Create default interfaces
    defNetIfWifiSta = esp_netif_create_default_wifi_sta();
    ESP_RETURN_ON_FALSE(defNetIfWifiSta, ESP_FAIL, TAG, "Failed to create the default STA interface");
    ESP_RETURN_ON_ERROR(setNetifHostname(defNetIfWifiSta, hostname), TAG, "Failed to set the initial STA hostname");

    defNetIfWifiAp = esp_netif_create_default_wifi_ap();
    ESP_RETURN_ON_FALSE(defNetIfWifiAp, ESP_FAIL, TAG, "Failed to create the default AP interface");
    ESP_RETURN_ON_ERROR(setNetifHostname(defNetIfWifiAp, hostname), TAG, "Failed to set the initial AP hostname");
    ESP_RETURN_ON_ERROR(setCustomAddressInAP(defNetIfWifiAp), TAG, "Failed to configure a custom IP address for the AP interface");

    // Register event handlers
    ESP_RETURN_ON_ERROR(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &onEvent, nullptr), TAG,
                        "Failed to register the event handler");
    ESP_RETURN_ON_ERROR(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &onEvent, nullptr), TAG,
                        "Failed to register the IPv4 event handler");
    ESP_RETURN_ON_ERROR(esp_event_handler_register(IP_EVENT, IP_EVENT_GOT_IP6, &onEvent, nullptr), TAG,
                        "Failed to register the IPv6 event handler");

    // Initialize Wi-Fi engine
    cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_RETURN_ON_ERROR(esp_wifi_init(&cfg), TAG, "Failed to initialize the driver");
    ESP_RETURN_ON_ERROR(esp_wifi_set_storage(WIFI_STORAGE_FLASH), TAG, "Failed to select flash storage");

    // Get stored configuration
    memset(&staConfig, 0, sizeof(staConfig));
    provisioned = false;
    ESP_RETURN_ON_ERROR(esp_wifi_get_config(WIFI_IF_STA, &staConfig), TAG, "Failed to read the stored STA configuration");
    provisioned = staConfig.sta.ssid[0] != 0;

    maxWifiPower = config->maxWifiPower;

    // If provisioned, start STA mode
    if (provisioned) {
        ESP_LOGI(TAG, "Stored credentials were found; starting STA mode.");
        ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "Failed to set STA mode");
        ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "Failed to start the interface");

        // Set the maximum transmit power
        ESP_RETURN_ON_ERROR(setWifiTxPower(maxWifiPower), TAG, "Failed to set TX power");
    }
    else {
        wifi_config_t apConfig;
        httpd_config_t serverConfig;
        httpd_uri_t catchAllHandler;
        esp_err_t ret;

        ESP_LOGI(TAG, "No stored credentials were found; starting the provisioning SoftAP.");

        // Setup AP configuration
        memset(&apConfig, 0, sizeof(apConfig));
        strlcpy((char *)apConfig.ap.ssid, config->softAP.ssid, sizeof(apConfig.ap.ssid));
        if (config->softAP.password && *config->softAP.password != 0) {
            strlcpy((char *)apConfig.ap.password, config->softAP.password, sizeof(apConfig.ap.password));
            apConfig.ap.authmode = WIFI_AUTH_WPA2_PSK;
        }
        else {
            apConfig.ap.authmode = WIFI_AUTH_OPEN;
        }
        apConfig.ap.channel = config->softAP.channel ? config->softAP.channel : 1;
        apConfig.ap.max_connection = 8;
        apConfig.ap.pairwise_cipher = WIFI_CIPHER_TYPE_CCMP;
        apConfig.ap.ftm_responder = false;
        apConfig.ap.pmf_cfg.capable = true;
        apConfig.ap.pmf_cfg.required  = false;
        apConfig.ap.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;

        // Start Wi-Fi in AP mode
        ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_APSTA), TAG, "Failed to set AP+STA mode");
        ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_AP, &apConfig), TAG, "Failed to configure AP mode");
        ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "Failed to start the interface");

        // Set the maximum transmit power
        ESP_RETURN_ON_ERROR(setWifiTxPower(maxWifiPower), TAG, "Failed to set TX power");

        // Setup DNS and DHCP for captive portal
        ESP_RETURN_ON_ERROR(captivePortalSetupDhcpUrl(), TAG, "Failed to configure the DHCP captive portal URI");
        ESP_RETURN_ON_ERROR(captivePortalSetupDns(), TAG, "Failed to configure catch-all DNS");

        // Call the custom captive portal initialization callback
        if (config->softAP.captivePortal.init) {
            ret = config->softAP.captivePortal.init(config->softAP.captivePortal.ctx);
            if (ret != ESP_OK) {
                return ret;
            }
        }

        // Save captive portal handlers
        cpHttpReqHandler = config->softAP.captivePortal.httpReq;
        cpDeinitHandler = config->softAP.captivePortal.deinit;
        cpHandlerCtx = config->softAP.captivePortal.ctx;

        // Initialize the HTTP server
        serverConfig = HTTPD_DEFAULT_CONFIG();
        serverConfig.uri_match_fn = httpd_uri_match_wildcard;
        ESP_GOTO_ON_ERROR(httpd_start(&cpHttpServer, &serverConfig), after_http, TAG, "Failed to start the HTTP server");

        memset(&catchAllHandler, 0, sizeof(catchAllHandler));
        catchAllHandler.uri = "/*";
        catchAllHandler.method = (httpd_method_t)HTTP_ANY;
        catchAllHandler.handler = captivePortalCatchAllHandler;
        ESP_GOTO_ON_ERROR(httpd_register_uri_handler(cpHttpServer, &catchAllHandler), after_http, TAG, "Failed to register the HTTP handler");

        ret = ESP_OK;
after_http:
        if (ret != ESP_OK) {
            stopCaptivePortal();
            return ret;
        }
    }

    ESP_RETURN_ON_ERROR(esp_wifi_set_ps(WIFI_PS_NONE), TAG, "Failed to disable power saving");

    // Done
    return ESP_OK;
}

static esp_err_t setNetifHostname(esp_netif_t *netIf, const char *hostname)
{
    const char *effectiveHostname = (hostname && *hostname != 0) ? hostname : CONFIG_LWIP_LOCAL_HOSTNAME;

    return esp_netif_set_hostname(netIf, effectiveHostname);
}

static void onEvent(void *arg, esp_event_base_t eventBase, int32_t eventId, void *eventData)
{
    if (eventBase == WIFI_EVENT) {
        switch (eventId) {
            case WIFI_EVENT_STA_START:
                {
                    AutoRundownProtection rpLock(rp);

                    if (rpLock.acquired() && provisioned) {
                        esp_wifi_connect();
                    }
                }
                break;

            case WIFI_EVENT_STA_DISCONNECTED:
                {
                    AutoRundownProtection rpLock(rp);
                    wifi_event_sta_disconnected_t *event = (wifi_event_sta_disconnected_t *)eventData;

                    ESP_LOGI(TAG, "Disconnected (reason=%u, rssi=%d); reconnecting to the configured access point.", event->reason,
                             event->rssi);

                    if (rpLock.acquired() && provisioned) {
                        // Raise disconnected state or notify if authentication failed
                        if (connected) {
                            connected = false;
                            handler(WifiMgrEventDisconnected, handlerCtx);
                        }
                        else {
                            if (event->reason == WIFI_REASON_AUTH_FAIL) {
                                handler(WifiMgrEventAuthenticationFailed, handlerCtx);
                            }
                        }

                        esp_wifi_connect();
                    }
                }
                break;

            case WIFI_EVENT_AP_START:
                ESP_LOGI(TAG, "Access point started.");
                break;

            case WIFI_EVENT_AP_STOP:
                ESP_LOGI(TAG, "Access point stopped.");
                break;
        }
    }
    else if (eventBase == IP_EVENT) {
        switch (eventId) {
            case IP_EVENT_STA_GOT_IP:
                {
                    AutoRundownProtection rpLock(rp);
                    ip_event_got_ip_t *event = (ip_event_got_ip_t *)eventData;

                    ESP_LOGI(TAG, "Connected; acquired IPv4 address " IPSTR ".", IP2STR(&event->ip_info.ip));
                    if (rpLock.acquired()) {
                        // Raise connected state
                        if (!connected) {
                            connected = true;
                            handler(WifiMgrEventConnected, handlerCtx);
                        }
                    }
                }
                break;

            case IP_EVENT_GOT_IP6:
                {
                    AutoRundownProtection rpLock(rp);
                    ip_event_got_ip6_t *event = (ip_event_got_ip6_t *)eventData;

                    ESP_LOGI(TAG, "Connected; acquired IPv6 address " IPV6STR ".", IPV62STR(event->ip6_info.ip));
                    if (rpLock.acquired()) {
                        // Raise connected state
                        if (!connected) {
                            connected = true;
                            handler(WifiMgrEventConnected, handlerCtx);
                        }
                    }
                }
                break;
        }
    }
}

static void staTransitionTimerCallback(void *arg)
{
    AutoRundownProtection rpLock(rp);

    if (rpLock.acquired()) {
        performStaModeTransition();
    }
}

static void performStaModeTransition()
{
    AutoMutex lock(mtx);
    char hostname[MAX_HOSTNAME_LEN + 1];
    esp_err_t err;

    staTransitionPending = false;

    ESP_LOGI(TAG, "Switching from provisioning SoftAP mode to STA mode.");

    stopCaptivePortal();

    err = esp_wifi_stop();
    if (err != ESP_OK && err != ESP_ERR_WIFI_NOT_STARTED) {
        ESP_LOGE(TAG, "Failed to stop the interface before switching to STA mode. Error: %d.", err);
        return;
    }

    err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to switch to STA mode. Error: %d.", err);
        return;
    }

    err = loadStoredHostnameOrDefault(hostname);
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
        ESP_LOGE(TAG, "Failed to read the STA hostname before switching modes. Error: %d.", err);
        return;
    }

    err = setNetifHostname(defNetIfWifiSta, hostname);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set the STA hostname before switching modes. Error: %d.", err);
        return;
    }

    err = esp_wifi_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start STA mode. Error: %d.", err);
    }

    err = setWifiTxPower(maxWifiPower);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set TX power. Error: %d.", err);
    }
}

static esp_err_t setWifiTxPower(float power)
{
    int8_t maxTxPower;

    if (power < 0.0001) {
        return ESP_OK;
    }

    // Set the maximum transmit power (34 * 0.25 dBm = 8.5 dBm)
    if (power < 8.0f) {
        maxTxPower = 32;
    }
    else if (power > 20.0f) {
        maxTxPower = 80;
    }
    else {
        maxTxPower = (int8_t)(power * 4.0f + 0.0001f);
    }
    return esp_wifi_set_max_tx_power(maxTxPower);
}

static esp_err_t loadStoredHostnameOrDefault(char hostname[MAX_HOSTNAME_LEN + 1])
{
    NVSStorage storage(NVSNamespace);
    lightstd::string value;
    esp_err_t err;

    hostname[0] = 0;

    err = storage.readStr(NVSKeyHostname, value);
    if (err == ESP_OK) {
        if (value.length() != 0 && value.length() <= MAX_HOSTNAME_LEN && isValidHostname(value.c_str())) {
            strlcpy(hostname, value.c_str(), MAX_HOSTNAME_LEN + 1);
        }
        else {
            err = ESP_ERR_INVALID_RESPONSE;
        }
    }
    if (err != ESP_OK) {
        strlcpy(hostname, CONFIG_LWIP_LOCAL_HOSTNAME, MAX_HOSTNAME_LEN + 1);
    }
    return err;
}

static esp_err_t saveStoredHostname(const char *hostname)
{
    NVSStorage storage(NVSNamespace);
    esp_err_t err;

    if (!hostname || hostname[0] == 0) {
        return eraseStoredHostname();
    }
    if (!isValidHostname(hostname)) {
        return ESP_ERR_INVALID_ARG;
    }

    err = storage.writeStr(NVSKeyHostname, hostname);
    if (err != ESP_OK) {
        return err;
    }

    return storage.commit();
}

static esp_err_t eraseStoredHostname()
{
    NVSStorage storage(NVSNamespace);
    esp_err_t err;

    err = storage.erase(NVSKeyHostname);
    if (err != ESP_OK) {
        return err;
    }

    return storage.commit();
}

static esp_err_t setCustomAddressInAP(esp_netif_t *netIf)
{
    esp_err_t err;

    err = esp_netif_dhcps_stop(netIf);
    if (err == ESP_OK) {
        esp_netif_ip_info_t ipInfo;

        memset(&ipInfo, 0, sizeof(ipInfo));
        ipInfo.ip.addr = ESP_IP4TOADDR(4, 3, 2, 1);
        ipInfo.gw.addr = ESP_IP4TOADDR(4, 3, 2, 1);
        ipInfo.netmask.addr = ESP_IP4TOADDR(255, 0, 0, 0);
        err = esp_netif_set_ip_info(netIf, &ipInfo);
    }
    if (err == ESP_OK) {
        esp_netif_dns_info_t dnsInfo;
        uint8_t opt = 1;

        memset(&dnsInfo, 0, sizeof(dnsInfo));
        dnsInfo.ip.type = ESP_IPADDR_TYPE_V4;
        dnsInfo.ip.u_addr.ip4.addr = ESP_IP4TOADDR(4, 3, 2, 1);
        err = esp_netif_set_dns_info(netIf, ESP_NETIF_DNS_MAIN, &dnsInfo);
        if (err == ESP_OK) {
            err = esp_netif_dhcps_option(netIf, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &opt, sizeof(opt));
        }
    }
    if (err == ESP_OK) {
        dhcps_lease_t dhcpLease;

        memset(&dhcpLease, 0, sizeof(dhcpLease));
        dhcpLease.enable = true;
        IP4_ADDR(&dhcpLease.start_ip, 4, 3, 2, 2);
        IP4_ADDR(&dhcpLease.end_ip, 4, 3, 2, 100);
        err = esp_netif_dhcps_option(netIf, ESP_NETIF_OP_SET, ESP_NETIF_REQUESTED_IP_ADDRESS, &dhcpLease, sizeof(dhcpLease));
    }

    if (err == ESP_OK) {
        err = esp_netif_dhcps_start(netIf);
    }

    return err;
}

static esp_err_t captivePortalSetupDhcpUrl()
{
    esp_netif_t *netIf;
    esp_netif_ip_info_t ipInfo;
    char ipAddr[16];
    esp_err_t err;

    netIf = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (!netIf) {
        return ESP_FAIL;
    }
    err = esp_netif_get_ip_info(netIf, &ipInfo);
    if (err != ESP_OK) {
        return err;
    }

    inet_ntoa_r(ipInfo.ip.addr, ipAddr, 16);
    strlcpy(cpDhcpUri, "http://", sizeof(cpDhcpUri));
    strlcat(cpDhcpUri, ipAddr, sizeof(cpDhcpUri));

    err = esp_netif_dhcps_stop(netIf);
    if (err == ESP_OK) {
        err = esp_netif_dhcps_option(netIf, ESP_NETIF_OP_SET, ESP_NETIF_CAPTIVEPORTAL_URI, cpDhcpUri, strlen(cpDhcpUri));
        if (err == ESP_OK) {
            err = esp_netif_dhcps_start(netIf);
        }
    }
    if (err != ESP_OK) {
        return err;
    }

    return err;
}

static esp_err_t captivePortalSetupDns()
{
    esp_netif_t *netIf;
    esp_netif_ip_info_t ipInfo;
    sockaddr_in addr;
    esp_err_t err;

    netIf = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (!netIf) {
        return ESP_FAIL;
    }
    err = esp_netif_get_ip_info(netIf, &ipInfo);
    if (err != ESP_OK) {
        return err;
    }

    {
        AutoMutex lock(cpDnsMtx);

        cpDnsIP[0] = esp_ip4_addr1(&ipInfo.ip);
        cpDnsIP[1] = esp_ip4_addr2(&ipInfo.ip);
        cpDnsIP[2] = esp_ip4_addr3(&ipInfo.ip);
        cpDnsIP[3] = esp_ip4_addr4(&ipInfo.ip);
    }

    cpDnsSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (cpDnsSocket < 0) {
        ESP_LOGE(TAG, "Failed to create the DNS socket.");
        return ESP_FAIL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(cpDnsSocket, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind the DNS socket.");
        close(cpDnsSocket);
        cpDnsSocket = -1;
        return ESP_FAIL;
    }

    err = taskCreate(&cpDnsTask, cpDnsServerTask, "cp_dns_server", 4096, nullptr, 4, tskNO_AFFINITY);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start the DNS server. Error: %d.", err);
        close(cpDnsSocket);
        cpDnsSocket = -1;
        return err;
    }

    return ESP_OK;
}

static esp_err_t captivePortalCatchAllHandler(httpd_req_t *req)
{
    if (!cpHttpReqHandler) {
        return ESP_FAIL;
    }

    return cpHttpReqHandler(req, cpHandlerCtx);
}

static void cpDnsServerTask(Task_t *task, void *arg)
{
    uint8_t rxBuffer[512];

    taskSignalContinue(task);

    while (!taskShouldQuit(task)) {
        sockaddr_in srcAddr = {};
        socklen_t srcAddrLen = sizeof(srcAddr);
        uint8_t dnsIP[4];
        int dnsSocket;
        int len;
        int idx;

        {
            AutoMutex lock(cpDnsMtx);

            dnsSocket = cpDnsSocket;
            memcpy(dnsIP, cpDnsIP, sizeof(dnsIP));
        }
        if (dnsSocket < 0) {
            break;
        }

        len = recvfrom(dnsSocket, rxBuffer, sizeof(rxBuffer), 0, reinterpret_cast<sockaddr *>(&srcAddr), &srcAddrLen);

        if (taskShouldQuit(task)) {
            break;
        }
        if (len < 0) {
            continue;
        }
        if (len < 12) {
            continue;
        }

        rxBuffer[2] |= 0x80;
        rxBuffer[3] |= 0x80;
        rxBuffer[7] = 1;

        idx = 12;
        while (idx < len && rxBuffer[idx] != 0) {
            idx += rxBuffer[idx] + 1;
        }
        idx += 5;
        if (idx + 16 > static_cast<int>(sizeof(rxBuffer))) {
            continue;
        }

        rxBuffer[idx++] = 0xC0;
        rxBuffer[idx++] = 0x0C;
        rxBuffer[idx++] = 0x00;
        rxBuffer[idx++] = 0x01;
        rxBuffer[idx++] = 0x00;
        rxBuffer[idx++] = 0x01;
        rxBuffer[idx++] = 0x00;
        rxBuffer[idx++] = 0x00;
        rxBuffer[idx++] = 0x00;
        rxBuffer[idx++] = 0x3C;
        rxBuffer[idx++] = 0x00;
        rxBuffer[idx++] = 0x04;
        rxBuffer[idx++] = dnsIP[0];
        rxBuffer[idx++] = dnsIP[1];
        rxBuffer[idx++] = dnsIP[2];
        rxBuffer[idx++] = dnsIP[3];

        sendto(dnsSocket, rxBuffer, idx, 0, reinterpret_cast<sockaddr *>(&srcAddr), srcAddrLen);
    }
}

static void stopCaptivePortal()
{
    int dnsSocketToClose = -1;

    if (cpHttpServer) {
        httpd_stop(cpHttpServer);
        cpHttpServer = nullptr;
    }

    {
        AutoMutex lock(cpDnsMtx);

        dnsSocketToClose = cpDnsSocket;
        cpDnsSocket = -1;
    }

    if (taskIsRunning(&cpDnsTask)) {
        if (dnsSocketToClose >= 0) {
            close(dnsSocketToClose);
        }

        taskJoin(&cpDnsTask);
        taskInit(&cpDnsTask);
    }
    else if (dnsSocketToClose >= 0) {
        close(dnsSocketToClose);
    }

    {
        AutoMutex lock(cpDnsMtx);

        memset(cpDnsIP, 0, sizeof(cpDnsIP));
    }
    memset(cpDhcpUri, 0, sizeof(cpDhcpUri));

    if (cpDeinitHandler) {
        cpDeinitHandler(cpHandlerCtx);
    }
    cpDeinitHandler = nullptr;
    cpHttpReqHandler = nullptr;
    cpHandlerCtx = nullptr;
}
