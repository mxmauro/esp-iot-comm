#pragma once

#include <esp_err.h>
#include <esp_http_server.h>
#include <stdint.h>

// -----------------------------------------------------------------------------

typedef enum WifiMgrEvent_e {
    WifiMgrEventConnected    = 1,
    WifiMgrEventDisconnected = 2
} WifiMgrEvent_t;

typedef void (*WifiMgrEventHandler_t)(WifiMgrEvent_t event, void *ctx);

typedef esp_err_t (*WifiMgrCaptivePortalInitCallback_t)(void *ctx);
typedef void (*WifiMgrCaptivePortalDoneCallback_t)(void *ctx);
typedef esp_err_t (*WifiMgrCaptivePortalHttpRequestHandler_t)(httpd_req_t *req, void *ctx);

typedef struct WifiMgrSoftApCaptivePortalConfig_s {
    WifiMgrCaptivePortalInitCallback_t       init;
    WifiMgrCaptivePortalDoneCallback_t       done;
    WifiMgrCaptivePortalHttpRequestHandler_t httpReq;
    void                                     *ctx;
} WifiMgrSoftApCaptivePortalConfig_t;

typedef struct WifiMgrSoftApConfig_s {
    const char                         *ssid;
    const char                         *password;
    uint8_t                            channel; // Defaults to 1 if zero
    WifiMgrSoftApCaptivePortalConfig_t captivePortal;
} WifiMgrSoftApConfig_t;

typedef struct WifiMgrConfig_s {
    WifiMgrEventHandler_t handler;
    void                  *handlerCtx;
    WifiMgrSoftApConfig_t softAP;
} WifiMgrConfig_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t wifiMgrInit(WifiMgrConfig_t *config);
void wifiMgrDeinit();

bool wifiMgrIsProvisioned();
bool wifiMgrDeleteConfig();

esp_err_t wifiMgrStoreSTA(const char *ssid, const char *password);
esp_err_t wifiMgrStartSTA();

esp_err_t wifiMgrGetApIPAddress(uint8_t ip[4]);

#ifdef __cplusplus
}
#endif // __cplusplus
