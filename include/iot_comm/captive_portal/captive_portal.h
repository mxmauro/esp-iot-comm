#pragma once

#include "iot_comm/utils/network.h"
#include "iot_comm/crypto/p256.h"
#include <esp_err.h>
#include <esp_http_server.h>

// -----------------------------------------------------------------------------

// Holds the Wi-Fi and device setup data gathered from the captive portal workflow.
typedef struct CaptivePortalSetupData_s {
    char    wifiSSID[32];
    char    wifiPassword[64];
    uint8_t rootUserPublicKey[P256_PUBLIC_KEY_SIZE];
    char    hostname[MAX_HOSTNAME_LEN + 1];
} CaptivePortalSetupData_t;

// Receives the setup data submitted through the captive portal.
typedef esp_err_t (*CaptivePortalSetupDataHandler_t)(CaptivePortalSetupData_t *setupData, void *ctx);

// Configures how the captive portal collects and applies setup data.
typedef struct CaptivePortalConfig_s {
    CaptivePortalSetupDataHandler_t handler;
    void *handlerCtx;
    bool setupRootUser;
    bool setupDeviceHostname;
} CaptivePortalConfig_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Initializes the captive portal subsystem.
esp_err_t capPortalInit(CaptivePortalConfig_t *config);
// Releases resources owned by the captive portal subsystem.
void capPortalDeinit();

// Processes an incoming HTTP request for the captive portal.
esp_err_t capPortalHandleRequest(httpd_req_t *req);

#ifdef __cplusplus
}
#endif // __cplusplus

// -----------------------------------------------------------------------------
