#pragma once

#include <esp_err.h>
#include <esp_http_server.h>
#include <iot_comm/utils/network.h>
#include <stdint.h>

// -----------------------------------------------------------------------------

// Identifies Wi-Fi manager state changes reported to the application.
typedef enum WifiMgrEvent_e {
    WifiMgrEventConnected            = 1,
    WifiMgrEventDisconnected         = 2,
    WifiMgrEventAuthenticationFailed = 3
} WifiMgrEvent_t;

// Receives Wi-Fi manager events.
typedef void (*WifiMgrEventHandler_t)(WifiMgrEvent_t event, void *ctx);

// Performs captive portal setup before the SoftAP server starts handling requests.
typedef esp_err_t (*WifiMgrCaptivePortalInitCallback_t)(void *ctx);
// Cleans up captive portal state after the SoftAP workflow ends.
typedef void (*WifiMgrCaptivePortalDeinitCallback_t)(void *ctx);
// Handles HTTP requests that should be served by the captive portal.
typedef esp_err_t (*WifiMgrCaptivePortalHttpRequestHandler_t)(httpd_req_t *req, void *ctx);

// Groups the captive portal callbacks used while provisioning through SoftAP.
typedef struct WifiMgrSoftApCaptivePortalConfig_s {
    WifiMgrCaptivePortalInitCallback_t       init;
    WifiMgrCaptivePortalDeinitCallback_t     deinit;
    WifiMgrCaptivePortalHttpRequestHandler_t httpReq;
    void                                     *ctx;
} WifiMgrSoftApCaptivePortalConfig_t;

// Defines the SoftAP settings used during provisioning.
typedef struct WifiMgrSoftApConfig_s {
    const char                         *ssid;
    const char                         *password;
    uint8_t                            channel; // Defaults to 1 if zero
    WifiMgrSoftApCaptivePortalConfig_t captivePortal;
} WifiMgrSoftApConfig_t;

// Holds the top-level configuration for the Wi-Fi manager.
typedef struct WifiMgrConfig_s {
    WifiMgrEventHandler_t handler;
    void                  *handlerCtx;
    WifiMgrSoftApConfig_t softAP;
    float                 maxWifiPower; // In dBm, between 8 and 20. 0 To use default setting.
} WifiMgrConfig_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Initializes the Wi-Fi manager and provisioning workflow.
esp_err_t wifiMgrInit(WifiMgrConfig_t *config);
// Releases resources owned by the Wi-Fi manager.
void wifiMgrDeinit();

// Reports whether station credentials have already been stored.
bool wifiMgrIsProvisioned();
// Removes any stored Wi-Fi provisioning data.
bool wifiMgrDeleteConfig();

// Stores the device hostname and applies it to active Wi-Fi interfaces.
// This can be called without initializing the Wi-Fi manager.
esp_err_t wifiMgrSetHostname(const char *hostname);

// Reads the stored device hostname or returns CONFIG_LWIP_LOCAL_HOSTNAME when unset.
// This can be called without initializing the Wi-Fi manager.
esp_err_t wifiMgrGetHostname(char hostname[MAX_HOSTNAME_LEN + 1]);

// Persists station credentials for later connection attempts.
esp_err_t wifiMgrStoreSTA(const char *ssid, const char *password);

// Starts connecting in station mode using the stored credentials.
esp_err_t wifiMgrStartSTA();

// Returns the IPv4 address assigned to the provisioning access point.
esp_err_t wifiMgrGetApIPAddress(uint8_t ip[4]);

#ifdef __cplusplus
}
#endif // __cplusplus
