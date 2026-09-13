#pragma once

#include "iot_comm/utils/network.h"
#include "iot_comm/crypto/p256.h"
#include <esp_err.h>
#include <esp_http_server.h>

// -----------------------------------------------------------------------------

// Holds the validated Wi-Fi and device provisioning config gathered from the captive portal workflow.
typedef struct CaptivePortalProvisioningConfig_s {
    char    wifiSSID[32];
    char    wifiPassword[64];
    uint8_t rootUserPublicKey[P256_PUBLIC_KEY_SIZE];
    char    hostname[MAX_HOSTNAME_LEN + 1];
} CaptivePortalProvisioningConfig_t;

// Receives the validated provisioning config submitted through the captive portal.
typedef esp_err_t (*CaptivePortalProvisioningConfigHandler_t)(CaptivePortalProvisioningConfig_t* config, void* ctx);
// Verifies the root-user signature authorizing recovery provisioning.
typedef esp_err_t (*CaptivePortalRootAuthorizationHandler_t)(const uint8_t hash[P256_HASH_SIZE],
                                                             const uint8_t signature[P256_SIGNATURE_SIZE], void* ctx);

// Configures how the captive portal collects and applies provisioning data.
typedef struct CaptivePortalConfig_s {
    CaptivePortalProvisioningConfigHandler_t handler;
    void*                                    handlerCtx;
    CaptivePortalRootAuthorizationHandler_t  rootAuthorization;
    void*                                    rootAuthorizationCtx;
    bool                                     requestWifiCredentials;
    bool                                     setupRootUser;
    bool                                     setupDeviceHostname;
    bool                                     requireRootAuthorization;
} CaptivePortalConfig_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Initializes the captive portal subsystem.
esp_err_t capPortalInit(CaptivePortalConfig_t* config);
// Releases resources owned by the captive portal subsystem.
void capPortalDeinit();

// Processes an incoming HTTP request for the captive portal.
esp_err_t capPortalHandleRequest(httpd_req_t* req);

#ifdef __cplusplus
}
#endif // __cplusplus

// -----------------------------------------------------------------------------
