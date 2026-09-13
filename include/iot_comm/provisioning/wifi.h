#pragma once

#include <esp_err.h>
#include <esp_http_server.h>
#include <iot_comm/utils/network.h>
#include <mdns.h>
#include <stddef.h>
#include <stdint.h>

// -----------------------------------------------------------------------------

// Identifies Wi-Fi manager state changes reported to the application.
typedef enum WifiMgrEvent_e {
    WifiMgrEventConnected = 1,
    WifiMgrEventDisconnected = 2,
    WifiMgrEventAuthenticationFailed = 3,
    WifiMgrEventProvisioningRequired = 4,
    WifiMgrEventProvisioningStarted = 5,
    WifiMgrEventProvisioningStopped = 6
} WifiMgrEvent_t;

// Receives Wi-Fi manager events.
typedef void (*WifiMgrEventHandler_t)(WifiMgrEvent_t event, void* ctx);

// Starts a provisioning application after the SoftAP and DNS services are ready.
typedef esp_err_t (*WifiMgrProvisioningStartCallback_t)(void* ctx);
// Stops the provisioning application before the SoftAP services are released.
typedef void (*WifiMgrProvisioningStopCallback_t)(void* ctx);
// Handles HTTP requests that should be served by the provisioning application.
typedef esp_err_t (*WifiMgrProvisioningHttpRequestHandler_t)(httpd_req_t* req, void* ctx);

// Groups the generic provisioning application callbacks hosted by the SoftAP.
typedef struct WifiMgrProvisioningHandlerConfig_s {
    WifiMgrProvisioningStartCallback_t      start;
    WifiMgrProvisioningStopCallback_t       stop;
    WifiMgrProvisioningHttpRequestHandler_t httpReq;
    void*                                   ctx;
} WifiMgrProvisioningHandlerConfig_t;

// Defines the SoftAP settings used during provisioning.
typedef struct WifiMgrSoftApConfig_s {
    const char* ssid;
    const char* password;
    uint8_t     channel; // Defaults to 1 if zero
} WifiMgrSoftApConfig_t;

// Holds the top-level configuration for the Wi-Fi manager.
typedef struct WifiMgrConfig_s {
    WifiMgrEventHandler_t handler;
    void*                 handlerCtx;
    float                 maxWifiPower; // In dBm, between 8 and 20. 0 To use default setting.
    uint32_t              staConnectTimeoutMs; // 0 disables connection-timeout provisioning notifications.
} WifiMgrConfig_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Initializes the Wi-Fi manager and starts STA when stored credentials are available.
esp_err_t wifiMgrInit(WifiMgrConfig_t* config);
// Releases resources owned by the Wi-Fi manager.
void wifiMgrDeinit();

// Reports whether station credentials have already been stored.
bool wifiMgrIsProvisioned();
// Removes any stored Wi-Fi provisioning data.
bool wifiMgrDeleteConfig();

// Stores the device hostname and applies it to active Wi-Fi interfaces.
// This can be called without initializing the Wi-Fi manager.
esp_err_t wifiMgrSetHostname(const char* hostname);

// Reads the stored device hostname or returns CONFIG_LWIP_LOCAL_HOSTNAME when unset.
// This can be called without initializing the Wi-Fi manager.
esp_err_t wifiMgrGetHostname(char hostname[MAX_HOSTNAME_LEN + 1]);

// Adds an mDNS service while the Wi-Fi manager is initialized.
esp_err_t wifiMgrMdnsServiceAdd(const char* instanceName, const char* serviceType, const char* proto, uint16_t port, mdns_txt_item_t txt[],
                                size_t numItems);
// Removes an mDNS service while the Wi-Fi manager is initialized.
esp_err_t wifiMgrMdnsServiceRemove(const char* serviceType, const char* proto);

// Starts a SoftAP, DNS catch-all, and HTTP dispatcher for an application-selected provisioning flow.
esp_err_t wifiMgrStartProvisioning(const WifiMgrSoftApConfig_t* softAP, const WifiMgrProvisioningHandlerConfig_t* handler);
// Reports whether the provisioning SoftAP, DNS, and HTTP dispatcher are active.
bool wifiMgrIsProvisioningActive();
// Stops the active SoftAP provisioning flow without changing stored STA credentials.
void wifiMgrStopProvisioning();

// Persists station credentials for later connection attempts.
esp_err_t wifiMgrStoreSTA(const char* ssid, const char* password);

// Starts connecting in station mode using the stored credentials.
esp_err_t wifiMgrStartSTA();

// Returns the IPv4 address assigned to the provisioning access point.
esp_err_t wifiMgrGetApIPAddress(uint8_t ip[4]);

#ifdef __cplusplus
}
#endif // __cplusplus
